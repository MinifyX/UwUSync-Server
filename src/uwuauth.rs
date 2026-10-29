//! Pairing with UwUAuth, from the command line: `uwusync-server uwuauth pair
//! <address> <code>`, `uwuauth status`, `uwuauth unpair`. See `docs/sso.md`.
//!
//! Pairing is UwUAuth's suite protocol: the operator makes a pairing code
//! there, this server hands it back with what it is, and UwUAuth answers with
//! an OpenID Connect client for it and a SCIM token to push people with. Both
//! are kept in the database, which the running server reads on every request
//! — so a pairing made while it runs counts at once.

use crate::config::Config;
use crate::db::sso::{self as people, Pairing};
use crate::db::Db;
use crate::{oidc, outbound};
use serde_json::{json, Value};

/// Where UwUAuth sends the browser back: the device's loopback listener. The
/// port is the device's own and changes every time; UwUAuth matches loopback
/// redirects without it (RFC 8252 §7.3).
pub const REDIRECT_URI: &str = "http://127.0.0.1/uwusync/callback";

/// The address and the code, as the operator gave them — or the code with the
/// address in it, as UwUAuth's QR code has it (`<address>#pair=<code>`).
pub fn pairing_input(url: Option<&str>, code: &str) -> Result<(String, String), String> {
    let code = code.trim();
    let (url, code) = match code.split_once("#pair=") {
        Some((from_qr, code)) => (
            url.map(str::trim)
                .filter(|url| !url.is_empty())
                .unwrap_or(from_qr),
            code,
        ),
        None => (url.map(str::trim).unwrap_or_default(), code),
    };
    let url = url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err("UwUAuth's address is missing.".into());
    }
    let parsed = oidc::checked_endpoint(&url, "UwUAuth's address")?;
    if parsed.query().is_some() {
        return Err("UwUAuth's address has no ?query.".into());
    }
    let code = code.trim().to_string();
    if code.is_empty() || code.len() > 64 || code.chars().any(char::is_control) {
        return Err("The pairing code from UwUAuth is missing.".into());
    }
    Ok((url, code))
}

/// This server's own address, as UwUAuth will reach it: https, because that is
/// where the browser and SCIM go, and set, because the address the server
/// listens on is not one anybody else can use.
pub fn public_url(config: &Config) -> Result<String, String> {
    if config.public.is_none() {
        return Err(
            "Set UWUSYNC_PUBLIC to the address devices and UwUAuth reach this \
                    server at (https://…) before pairing."
                .into(),
        );
    }
    let public = config.base_url();
    let parsed = reqwest::Url::parse(&public)
        .map_err(|_| format!("UWUSYNC_PUBLIC: {public} is not an address."))?;
    if parsed.scheme() != "https" {
        return Err(format!(
            "UwUAuth pairs only with a server at an https address; this one is {public}."
        ));
    }
    Ok(public)
}

/// Pair with the UwUAuth at `url`, with a code made there. What it says on
/// success, for the operator.
pub async fn pair(
    config: &Config,
    db: &Db,
    url: Option<&str>,
    code: &str,
) -> Result<String, String> {
    let (base, code) = pairing_input(url, code)?;
    let public = public_url(config)?;
    let client = outbound::client()?;
    let unreachable = |error: String| format!("UwUAuth did not answer: {error}");

    // 1. Is it UwUAuth, and does it pair?
    let response = client
        .get(format!("{base}/uwu/v1/server"))
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| unreachable(outbound::error_text(&error)))?;
    let not_uwuauth = || "This is not a UwUAuth that can pair (0.4 or newer).".to_string();
    let server: Value = oidc::read(response, "UwUAuth")
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(not_uwuauth)?;
    if server["product"] != "UwUAuth" || server["pairing"].as_i64().unwrap_or(0) < 1 {
        return Err(not_uwuauth());
    }
    let issuer = server["issuer"]
        .as_str()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    oidc::checked_issuer(&issuer)?;

    // 2. Pair.
    let host = reqwest::Url::parse(&public)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    let body = json!({
        "code": code,
        "app": {
            "product": "UwUSync",
            "version": env!("CARGO_PKG_VERSION"),
            "name": format!("UwUSync ({host})"),
            "url": public,
            "redirectUris": [REDIRECT_URI],
            "scopes": ["openid", "email", "profile"],
            "scim": {
                "baseUrl": format!("{public}/scim/v2"),
                "resources": ["User", "Group"],
                "userName": "email",
            },
        },
    });
    let response = client
        .post(format!("{base}/uwu/v1/pair"))
        .header("accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|error| unreachable(outbound::error_text(&error)))?;
    let status = response.status();
    let bytes = match status.as_u16() {
        200 => oidc::read(response, "UwUAuth").await?,
        400 | 429 => {
            let body = outbound::read_start(response, outbound::ERROR_BYTES * 16).await;
            let answer: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            return Err(match (status.as_u16(), answer["error"].as_str()) {
                (429, _) => "UwUAuth says: too many tries. Wait a quarter of an hour.".into(),
                (_, Some("invalid_code")) => {
                    "UwUAuth does not know this code (any more). Make a new one there.".into()
                }
                _ => {
                    let message = answer["message"]
                        .as_str()
                        .unwrap_or("it refused the pairing");
                    let field = answer["detail"]["field"]
                        .as_str()
                        .map(|field| format!(" ({field})"))
                        .unwrap_or_default();
                    format!("UwUAuth: {}{field}", printable(message))
                }
            });
        }
        _ => return Err(format!("UwUAuth answered {status}.")),
    };
    let answer: Value =
        serde_json::from_slice(&bytes).map_err(|_| "UwUAuth's answer is not JSON.".to_string())?;
    let text = |name: &str| {
        answer[name]
            .as_str()
            .map(str::to_string)
            .filter(|value| !value.is_empty())
    };
    let (Some(paired_issuer), Some(client_id), Some(client_secret)) =
        (text("issuer"), text("clientId"), text("clientSecret"))
    else {
        return Err("UwUAuth's answer lacks the issuer, the client id or its secret.".into());
    };
    if paired_issuer.trim_end_matches('/') != issuer {
        return Err("UwUAuth's answer names another issuer than it said before.".into());
    }
    // Can this server reach what it will need to, before keeping anything?
    let cache = oidc::Cache::default();
    oidc::discover(&cache, &issuer)
        .await
        .map_err(|error| format!("UwUAuth's discovery document: {error}"))?;

    // 3. Keep it.
    let pairing = Pairing {
        url: base.clone(),
        issuer: issuer.clone(),
        client_id,
        client_secret,
        scim_token_hash: text("scimToken").map(|token| crate::sha256(token.as_bytes()).to_vec()),
        app_id: text("appId"),
        manage_url: text("manageUrl"),
        paired_ms: crate::now_ms(),
    };
    let scim = pairing.scim_token_hash.is_some();
    people::set_pairing(&db.lock(), &pairing).map_err(|error| error.to_string())?;
    tracing::info!(%base, %issuer, scim, "paired with UwUAuth");
    let mut said = format!("Paired with UwUAuth at {base} (issuer {issuer}).");
    if scim {
        said.push_str("\nUwUAuth pushes who may sign in here over SCIM.");
    } else {
        said.push_str("\nUwUAuth sent no SCIM token: who signs in there may sign in here.");
    }
    if let Some(manage) = &pairing.manage_url {
        said.push_str(&format!("\nManage it in UwUAuth: {manage}"));
    }
    Ok(said)
}

/// Somebody else's text, fit for one line of a terminal.
fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(300).collect()
}

/// What `uwuauth status` prints.
pub fn status(db: &Db) -> Result<String, String> {
    let conn = db.lock();
    let Some(pairing) = people::pairing(&conn).map_err(|error| error.to_string())? else {
        return Ok(
            "Not paired with UwUAuth. `uwusync-server uwuauth pair <address> <code>` \
                   pairs with a code made there."
                .into(),
        );
    };
    let (_, people_count) =
        people::list(&conn, &pairing.issuer, 0, 0).map_err(|error| error.to_string())?;
    let mut said = format!(
        "Paired with UwUAuth at {} since {}.\nIssuer:    {}\nClient id: {}\nSCIM:      {}\nPeople:    {people_count}",
        pairing.url,
        crate::date(pairing.paired_ms),
        pairing.issuer,
        pairing.client_id,
        if pairing.scim_token_hash.is_some() {
            "on"
        } else {
            "off"
        },
    );
    if let Some(manage) = &pairing.manage_url {
        said.push_str(&format!("\nManage:    {manage}"));
    }
    Ok(said)
}

/// What `uwuauth unpair` does: forget the client and the SCIM token. People
/// and their accounts stay; signing in with UwUAuth stops until it pairs
/// again, and accounts made that way are still opened with their master
/// password on the devices that have them.
pub fn unpair(db: &Db) -> Result<String, String> {
    let was = people::unpair(&db.lock()).map_err(|error| error.to_string())?;
    Ok(if was {
        "Unpaired. Remove the app in UwUAuth as well; accounts and devices here stay.".into()
    } else {
        "Not paired with UwUAuth.".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_may_carry_the_address() {
        assert_eq!(
            pairing_input(None, "https://auth.example.com/#pair=ABCD-EFGH").unwrap(),
            ("https://auth.example.com".into(), "ABCD-EFGH".into())
        );
        assert_eq!(
            pairing_input(Some("https://auth.example.com/"), " ABCD ").unwrap(),
            ("https://auth.example.com".into(), "ABCD".into())
        );
        assert!(pairing_input(None, "ABCD").is_err());
        assert!(pairing_input(Some("http://auth.example.com"), "ABCD").is_err());
        assert!(pairing_input(Some("https://auth.example.com/?x=1"), "ABCD").is_err());
        assert!(pairing_input(Some("https://auth.example.com"), "").is_err());
    }
}

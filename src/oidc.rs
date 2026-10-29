//! UwUAuth as an OpenID Connect provider, from this server's side: its
//! discovery document and keys (kept for an hour), the code exchange, and the
//! check of an ID token. See `docs/sso.md`.
//!
//! The provider's address is the operator's to give, so it may be in the local
//! network; what is not allowed is being sent elsewhere: no redirect is
//! followed (the client of [`crate::outbound`]), every endpoint is https (or
//! http on a loopback address, for a provider on the same machine), and
//! answers are read up to a size.

use crate::outbound;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use parking_lot::Mutex;
use ring::signature;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a discovery document and keys are kept.
const KEEP: Duration = Duration::from_secs(60 * 60);
/// A token with a key the server does not know makes it fetch the keys again — at most this
/// often, so forged tokens do not turn into requests to the provider.
const REFETCH: Duration = Duration::from_secs(60);
/// The most an answer of the provider may be.
const MAX_ANSWER: usize = 512 * 1024;
/// Clocks may differ this much.
const LEEWAY: i64 = 60;
/// How long a failed fetch is remembered: while the provider fails, anonymous authorize calls
/// do not each ask it again .
const FAILED: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub usage: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Something fetched, and when.
type Fetched<T> = Mutex<HashMap<String, (Instant, Arc<T>)>>;

/// What was fetched, by address; what failed lately; and who is fetching right now.
#[derive(Default)]
pub struct Cache {
    discovery: Fetched<Discovery>,
    keys: Fetched<Vec<Jwk>>,
    failed: Mutex<HashMap<String, (Instant, String)>>,
    fetching: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Cache {
    /// Everything fetches again: the settings changed, or a restore brought others.
    pub fn forget(&self) {
        self.discovery.lock().clear();
        self.keys.lock().clear();
        self.failed.lock().clear();
    }

    /// Why fetching `url` failed, if it did within [`FAILED`].
    fn failed_lately(&self, url: &str) -> Option<String> {
        let mut failed = self.failed.lock();
        failed.retain(|_, (when, _)| when.elapsed() < FAILED);
        failed.get(url).map(|(_, error)| error.clone())
    }

    /// Fetches `url` once for everybody waiting: whoever comes while it runs waits and then
    /// finds the answer (or the failure) there.
    async fn once<T>(
        &self,
        url: &str,
        cached: impl Fn() -> Option<Arc<T>>,
        fetch: impl std::future::Future<Output = Result<Arc<T>, String>>,
    ) -> Result<Arc<T>, String> {
        if let Some(error) = self.failed_lately(url) {
            return Err(error);
        }
        let lock = self
            .fetching
            .lock()
            .entry(url.to_string())
            .or_default()
            .clone();
        let _held = lock.lock().await;
        if let Some(found) = cached() {
            return Ok(found);
        }
        if let Some(error) = self.failed_lately(url) {
            return Err(error);
        }
        let result = fetch.await;
        if let Err(error) = &result {
            self.failed
                .lock()
                .insert(url.to_string(), (Instant::now(), error.clone()));
        }
        self.fetching.lock().remove(url);
        result
    }
}

/// The issuer: an address of the provider's without a query, which would turn the fixed
/// discovery path into one.
pub fn checked_issuer(url: &str) -> Result<reqwest::Url, String> {
    let parsed = checked_endpoint(url, "The issuer")?;
    if parsed.query().is_some() || url.contains('?') {
        return Err(format!("The issuer: {url} cannot have a ?query."));
    }
    Ok(parsed)
}

/// An endpoint the discovery document names: http on loopback only when the issuer is on
/// loopback too, so a provider out there cannot send the client secret to a local service
///.
fn checked_for(url: &str, what: &str, issuer: &reqwest::Url) -> Result<reqwest::Url, String> {
    let parsed = checked_endpoint(url, what)?;
    if parsed.scheme() == "http" && !issuer.host_str().is_some_and(is_loopback) {
        return Err(format!(
            "{what}: {url} has to be an https address, like the issuer."
        ));
    }
    Ok(parsed)
}

/// An address of the provider's: https, or http on a loopback address.
pub fn checked_endpoint(url: &str, what: &str) -> Result<reqwest::Url, String> {
    let parsed =
        reqwest::Url::parse(url.trim()).map_err(|_| format!("{what}: {url} is not an address."))?;
    let Some(host) = parsed.host_str().filter(|host| !host.is_empty()) else {
        return Err(format!("{what}: {url} has no host."));
    };
    let loopback = is_loopback(host);
    match parsed.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(format!("{what}: {url} has to be an https address.")),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "{what}: {url} cannot carry credentials or a #fragment."
        ));
    }
    Ok(parsed)
}

/// `localhost`, `127.0.0.1`, `[::1]` and the like.
pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Read an answer, at most [`MAX_ANSWER`] of it; refused when it is not a success.
pub async fn read(response: reqwest::Response, what: &str) -> Result<Vec<u8>, String> {
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{what} {}", outbound::refused(response).await));
    }
    outbound::read_limited(response, MAX_ANSWER)
        .await
        .map_err(|error| format!("{what} {error}"))
}

async fn get_json<T: serde::de::DeserializeOwned>(
    url: &reqwest::Url,
    what: &str,
) -> Result<T, String> {
    let client = outbound::client()?;
    let response = client
        .get(url.clone())
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| format!("{what}: {}", outbound::error_text(&error)))?;
    let bytes = read(response, what).await?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{what} is not what it should be: {error}"))
}

/// The provider's discovery document for `issuer`, which must name itself as that issuer.
pub async fn discover(cache: &Cache, issuer: &str) -> Result<Arc<Discovery>, String> {
    let issuer = issuer.trim().trim_end_matches('/');
    if let Some((when, found)) = cache.discovery.lock().get(issuer) {
        if when.elapsed() < KEEP {
            return Ok(found.clone());
        }
    }
    let base = checked_issuer(issuer)?;
    let cached = || {
        cache
            .discovery
            .lock()
            .get(issuer)
            .filter(|(when, _)| when.elapsed() < KEEP)
            .map(|(_, found)| found.clone())
    };
    let fetch = async {
        let url = reqwest::Url::parse(&format!(
            "{}/.well-known/openid-configuration",
            base.as_str().trim_end_matches('/')
        ))
        .map_err(|error| error.to_string())?;
        let found: Discovery = get_json(&url, "The discovery document").await?;
        if found.issuer.trim_end_matches('/') != issuer {
            return Err(format!(
                "The discovery document names another issuer: {}",
                found.issuer
            ));
        }
        checked_for(
            &found.authorization_endpoint,
            "The authorization endpoint",
            &base,
        )?;
        checked_for(&found.token_endpoint, "The token endpoint", &base)?;
        checked_for(&found.jwks_uri, "The key set", &base)?;
        if let Some(userinfo) = &found.userinfo_endpoint {
            checked_for(userinfo, "The userinfo endpoint", &base)?;
        }
        let found = Arc::new(found);
        cache
            .discovery
            .lock()
            .insert(issuer.to_string(), (Instant::now(), found.clone()));
        Ok(found)
    };
    cache
        .once(&format!("discovery {issuer}"), cached, fetch)
        .await
}

/// The provider's signing keys; `again` fetches them anew unless that happened a minute ago.
pub async fn keys(
    cache: &Cache,
    discovery: &Discovery,
    again: bool,
) -> Result<Arc<Vec<Jwk>>, String> {
    if let Some((when, found)) = cache.keys.lock().get(&discovery.jwks_uri) {
        let fresh = when.elapsed() < KEEP && !(again && when.elapsed() >= REFETCH);
        if fresh {
            return Ok(found.clone());
        }
    }
    let url = checked_endpoint(&discovery.jwks_uri, "The key set")?;
    // Whoever waited while another fetched takes what that one found.
    let asked = Instant::now();
    let cached = || {
        cache
            .keys
            .lock()
            .get(&discovery.jwks_uri)
            .filter(|(when, _)| *when >= asked || (!again && when.elapsed() < KEEP))
            .map(|(_, found)| found.clone())
    };
    let fetch = async {
        let set: JwkSet = get_json(&url, "The key set").await?;
        let keys = Arc::new(
            set.keys
                .into_iter()
                .filter(|key| key.usage.as_deref() != Some("enc"))
                .collect::<Vec<_>>(),
        );
        cache
            .keys
            .lock()
            .insert(discovery.jwks_uri.clone(), (Instant::now(), keys.clone()));
        Ok(keys)
    };
    cache
        .once(&format!("keys {}", discovery.jwks_uri), cached, fetch)
        .await
}

/// What the token endpoint answered.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenAnswer {
    pub id_token: Option<String>,
    pub access_token: Option<String>,
}

/// The client's credentials at the provider.
pub struct ClientAuth<'a> {
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
}

/// Trade the provider's `code` for tokens: `client_secret_basic` (or `client_secret_post` when
/// that is all the provider takes), with the PKCE verifier.
pub async fn exchange(
    discovery: &Discovery,
    client: &ClientAuth<'_>,
    code: &str,
    redirect_uri: &str,
    verifier: Option<&str>,
) -> Result<TokenAnswer, String> {
    let url = checked_endpoint(&discovery.token_endpoint, "The token endpoint")?;
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
    ];
    if let Some(verifier) = verifier {
        form.push(("code_verifier", verifier.to_string()));
    }
    let methods = &discovery.token_endpoint_auth_methods_supported;
    let post_only = !methods.is_empty()
        && methods.iter().any(|method| method == "client_secret_post")
        && !methods.iter().any(|method| method == "client_secret_basic");
    let mut request = outbound::client()?
        .post(url)
        .header("accept", "application/json");
    match client.client_secret {
        Some(secret) if !post_only => {
            // RFC 6749 §2.3.1: both form-encoded before they go into the header.
            let pair = format!("{}:{}", form_encode(client.client_id), form_encode(secret));
            let basic = base64::engine::general_purpose::STANDARD.encode(pair);
            request = request.header("authorization", format!("Basic {basic}"));
        }
        Some(secret) => {
            form.push(("client_id", client.client_id.to_string()));
            form.push(("client_secret", secret.to_string()));
        }
        None => form.push(("client_id", client.client_id.to_string())),
    }
    let body = form
        .iter()
        .map(|(key, value)| format!("{key}={}", form_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let response = request
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|error| format!("The token endpoint: {}", outbound::error_text(&error)))?;
    let bytes = read(response, "The token endpoint").await?;
    serde_json::from_slice(&bytes).map_err(|error| format!("The token endpoint's answer: {error}"))
}

/// `application/x-www-form-urlencoded`, byte by byte.
pub fn form_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

// ── ID tokens ─────────────────────────────────────────────

/// What an ID token has to be for.
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
}

/// Why an ID token was refused. `UnknownKey` may go away with the provider's keys fetched anew.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    UnknownKey,
    Invalid(String),
}

fn invalid(reason: impl Into<String>) -> Refused {
    Refused::Invalid(reason.into())
}

/// The claims of `token`, when it is signed by one of `keys` and is for `expected`.
pub fn check_id_token(
    token: &str,
    keys: &[Jwk],
    expected: &Expected<'_>,
    now: i64,
) -> Result<Map<String, Value>, Refused> {
    let mut parts = token.trim().split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("not a signed JWT"));
    };
    let header: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| invalid("its header is not JSON"))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kid = header.get("kid").and_then(Value::as_str);
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| invalid("its signature is not base64url"))?;
    let signed = &token.trim()[..header_and_payload_len(token.trim())];
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|key| kid.is_none_or(|kid| key.kid.as_deref() == Some(kid)))
        .filter(|key| key.alg.as_deref().is_none_or(|key_alg| key_alg == alg))
        .collect();
    if candidates.is_empty() {
        return Err(Refused::UnknownKey);
    }
    let verified = candidates
        .iter()
        .any(|key| verify(alg, key, signed.as_bytes(), &signature).unwrap_or(false));
    if !verified {
        // An algorithm this server does not take is as good as no signature.
        return Err(invalid(format!("the signature ({alg}) does not verify")));
    }
    let claims: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| invalid("its claims are not JSON"))?;
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss").map(|iss| iss.trim_end_matches('/'))
        != Some(expected.issuer.trim_end_matches('/'))
    {
        return Err(invalid("it is from another issuer"));
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&expected.client_id) {
        return Err(invalid("it is for another client"));
    }
    if (audiences.len() > 1 || claims.contains_key("azp"))
        && text("azp").is_some_and(|azp| azp != expected.client_id)
    {
        return Err(invalid("it was handed to another client"));
    }
    let number = |name: &str| claims.get(name).and_then(Value::as_i64);
    match number("exp") {
        Some(exp) if exp + LEEWAY > now => {}
        _ => return Err(invalid("it ran out")),
    }
    if number("nbf").is_some_and(|nbf| nbf > now + LEEWAY)
        || number("iat").is_some_and(|iat| iat > now + 5 * LEEWAY)
    {
        return Err(invalid("it is from the future"));
    }
    let nonce = text("nonce").unwrap_or_default();
    if !crate::db::constant_time_eq(nonce.as_bytes(), expected.nonce.as_bytes()) {
        return Err(invalid("its nonce is not this login's"));
    }
    if text("sub").is_none_or(str::is_empty) {
        return Err(invalid("it names nobody (no sub)"));
    }
    Ok(claims)
}

fn header_and_payload_len(token: &str) -> usize {
    token.rfind('.').unwrap_or(0)
}

fn b64(value: Option<&String>) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value?.trim_end_matches('=')).ok()
}

/// Whether `signature` over `signed` verifies with `key` for `alg`; none for what is not taken.
fn verify(alg: &str, key: &Jwk, signed: &[u8], signature: &[u8]) -> Option<bool> {
    use signature::VerificationAlgorithm;
    let rsa = |params: &'static signature::RsaParameters| -> Option<bool> {
        if key.kty != "RSA" {
            return None;
        }
        let (n, e) = (b64(key.n.as_ref())?, b64(key.e.as_ref())?);
        Some(
            signature::RsaPublicKeyComponents { n: &n, e: &e }
                .verify(params, signed, signature)
                .is_ok(),
        )
    };
    let ec =
        |curve: &str, size: usize, algorithm: &'static dyn VerificationAlgorithm| -> Option<bool> {
            if key.kty != "EC" || key.crv.as_deref() != Some(curve) {
                return None;
            }
            let (x, y) = (b64(key.x.as_ref())?, b64(key.y.as_ref())?);
            if x.len() != size || y.len() != size {
                return Some(false);
            }
            let mut point = vec![4u8];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            Some(
                signature::UnparsedPublicKey::new(algorithm, point)
                    .verify(signed, signature)
                    .is_ok(),
            )
        };
    match alg {
        "RS256" => rsa(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => rsa(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => rsa(&signature::RSA_PKCS1_2048_8192_SHA512),
        "PS256" => rsa(&signature::RSA_PSS_2048_8192_SHA256),
        "PS384" => rsa(&signature::RSA_PSS_2048_8192_SHA384),
        "PS512" => rsa(&signature::RSA_PSS_2048_8192_SHA512),
        "ES256" => ec("P-256", 32, &signature::ECDSA_P256_SHA256_FIXED),
        "ES384" => ec("P-384", 48, &signature::ECDSA_P384_SHA384_FIXED),
        "EdDSA" if key.kty == "OKP" && key.crv.as_deref() == Some("Ed25519") => {
            let x = b64(key.x.as_ref())?;
            Some(
                signature::UnparsedPublicKey::new(&signature::ED25519, x)
                    .verify(signed, signature)
                    .is_ok(),
            )
        }
        // `none`, and HMAC with a secret the provider shares: never.
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    /// A key that signs ID tokens like a provider, and its JWK.
    pub(crate) enum Signer {
        Ec(EcdsaKeyPair),
        Ed(Ed25519KeyPair),
    }

    impl Signer {
        pub(crate) fn es256() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .unwrap();
            Signer::Ec(
                EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    pkcs8.as_ref(),
                    &rng,
                )
                .unwrap(),
            )
        }

        pub(crate) fn eddsa() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Signer::Ed(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        }

        pub(crate) fn jwk(&self, kid: &str) -> Value {
            match self {
                Signer::Ec(pair) => {
                    let point = pair.public_key().as_ref();
                    serde_json::json!({
                        "kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
                        "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..]),
                    })
                }
                Signer::Ed(pair) => serde_json::json!({
                    "kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA",
                    "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
                }),
            }
        }

        pub(crate) fn sign(&self, kid: &str, claims: &Value) -> String {
            let alg = match self {
                Signer::Ec(_) => "ES256",
                Signer::Ed(_) => "EdDSA",
            };
            let header = URL_SAFE_NO_PAD
                .encode(serde_json::json!({ "alg": alg, "kid": kid, "typ": "JWT" }).to_string());
            let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
            let signed = format!("{header}.{payload}");
            let signature = match self {
                Signer::Ec(pair) => pair
                    .sign(&SystemRandom::new(), signed.as_bytes())
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                Signer::Ed(pair) => pair.sign(signed.as_bytes()).as_ref().to_vec(),
            };
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
        }
    }

    fn keys_of(jwks: &[Value]) -> Vec<Jwk> {
        jwks.iter()
            .map(|jwk| serde_json::from_value(jwk.clone()).unwrap())
            .collect()
    }

    const NOW: i64 = 1_800_000_000;

    fn claims() -> Value {
        serde_json::json!({
            "iss": "https://auth.example.com", "aud": "sync", "sub": "p-1", "nonce": "n-1",
            "exp": NOW + 300, "iat": NOW, "email": "nyu@example.com",
        })
    }

    const EXPECTED: Expected<'static> = Expected {
        issuer: "https://auth.example.com",
        client_id: "sync",
        nonce: "n-1",
    };

    #[test]
    fn a_token_from_the_provider_for_this_login_passes() {
        for signer in [Signer::es256(), Signer::eddsa()] {
            let keys = keys_of(&[signer.jwk("k1")]);
            let token = signer.sign("k1", &claims());
            let found = check_id_token(&token, &keys, &EXPECTED, NOW).unwrap();
            assert_eq!(found["email"], "nyu@example.com");
        }
    }

    #[test]
    fn everything_that_makes_a_token_someone_else_s_is_refused() {
        let signer = Signer::es256();
        let keys = keys_of(&[signer.jwk("k1")]);
        let refused = |change: &dyn Fn(&mut Value)| {
            let mut changed = claims();
            change(&mut changed);
            check_id_token(&signer.sign("k1", &changed), &keys, &EXPECTED, NOW)
        };
        assert!(
            refused(&|c| c["iss"] = "https://evil.example.com".into()).is_err(),
            "issuer"
        );
        assert!(refused(&|c| c["aud"] = "other".into()).is_err(), "audience");
        assert!(
            refused(&|c| c["aud"] = serde_json::json!(["sync", "other"])).is_ok(),
            "among several"
        );
        assert!(
            refused(&|c| c["azp"] = "other".into()).is_err(),
            "handed to another client"
        );
        assert!(
            refused(&|c| c["exp"] = (NOW - 3600).into()).is_err(),
            "ran out"
        );
        assert!(
            refused(&|c| c["nonce"] = "n-2".into()).is_err(),
            "another login's nonce"
        );
        assert!(refused(&|c| c
            .as_object_mut()
            .unwrap()
            .remove("nonce")
            .map(drop)
            .unwrap_or(()))
        .is_err());
        assert!(refused(&|c| c["sub"] = "".into()).is_err(), "nobody");

        // Another key, an unknown key, a changed payload, no signature at all.
        let other = Signer::es256();
        assert!(check_id_token(&other.sign("k1", &claims()), &keys, &EXPECTED, NOW).is_err());
        assert_eq!(
            check_id_token(&other.sign("k9", &claims()), &keys, &EXPECTED, NOW),
            Err(Refused::UnknownKey)
        );
        let token = signer.sign("k1", &claims());
        let (head, rest) = token.split_once('.').unwrap();
        let (_, signature) = rest.split_once('.').unwrap();
        let mut forged = claims();
        forged["sub"] = "admin".into();
        let forged = format!(
            "{head}.{}.{signature}",
            URL_SAFE_NO_PAD.encode(forged.to_string())
        );
        assert!(check_id_token(&forged, &keys, &EXPECTED, NOW).is_err());
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"k1"}"#),
            URL_SAFE_NO_PAD.encode(claims().to_string())
        );
        assert!(
            check_id_token(&none, &keys, &EXPECTED, NOW).is_err(),
            "alg none"
        );
    }

    #[test]
    fn only_https_or_this_machine() {
        assert!(checked_endpoint("https://auth.example.com/token", "t").is_ok());
        assert!(checked_endpoint("http://127.0.0.1:9000/token", "t").is_ok());
        assert!(checked_endpoint("http://localhost:9000/token", "t").is_ok());
        for bad in [
            "http://auth.example.com/token",
            "ftp://auth.example.com",
            "https://u:p@auth.example.com",
            "nothing",
        ] {
            assert!(checked_endpoint(bad, "t").is_err(), "{bad}");
        }
        // No query in the issuer; loopback http only for a loopback issuer.
        assert!(checked_issuer("https://auth.example.com/realms/x").is_ok());
        for bad in [
            "https://auth.example.com/?",
            "https://auth.example.com/x?a=b",
            "https://auth.example.com/#x",
        ] {
            assert!(checked_issuer(bad).is_err(), "{bad}");
        }
        let out_there = checked_issuer("https://auth.example.com").unwrap();
        let local = checked_issuer("http://127.0.0.1:9000").unwrap();
        assert!(checked_for("http://127.0.0.1:8200/token", "t", &out_there).is_err());
        assert!(checked_for("https://auth.example.com/token", "t", &out_there).is_ok());
        assert!(checked_for("http://127.0.0.1:9000/token", "t", &local).is_ok());
    }

    #[tokio::test]
    async fn a_failing_provider_is_asked_once_and_then_left_alone() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let app = axum::Router::new().fallback(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let cache = Arc::new(Cache::default());
        let mut all = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (cache, issuer) = (cache.clone(), issuer.clone());
            all.spawn(async move { discover(&cache, &issuer).await.is_err() });
        }
        assert!(all.join_all().await.into_iter().all(|failed| failed));
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "once for everybody waiting"
        );
        assert!(discover(&cache, &issuer).await.unwrap_err().contains("503"));
        assert_eq!(asked.load(Ordering::SeqCst), 1, "the failure is remembered");
        cache.forget();
        assert!(discover(&cache, &issuer).await.is_err());
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "asked again once the settings change"
        );
    }
}

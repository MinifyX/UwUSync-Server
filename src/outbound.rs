//! Requests this server makes to UwUAuth: pairing, discovery, keys, the code
//! exchange.
//!
//! UwUAuth's address is the operator's to give, so it may well be in the local
//! network — that is fine. What is not fine is being sent on somewhere else:
//! no redirect is followed, nothing takes longer than ten seconds, and no
//! answer is read past a ceiling.
//!
//! The certificate is checked against the usual public roots, plus the PEM
//! file `UWUSYNC_UWUAUTH_CA` names, for a UwUAuth behind a private CA.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// How long any of these requests may take.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// What an error answer is read of, at most: enough for its message.
pub const ERROR_BYTES: usize = 4 * 1024;

/// A JSON answer of UwUAuth, at most.
pub const JSON_BYTES: usize = 512 * 1024;

/// The environment variable naming extra trusted roots (PEM).
pub const CA_VARIABLE: &str = "UWUSYNC_UWUAUTH_CA";

/// The client: no redirects, a short timeout, rustls with `ring`.
pub fn client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let mut roots: rustls::RootCertStore =
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            if let Some(path) = std::env::var_os(CA_VARIABLE).filter(|path| !path.is_empty()) {
                add_roots(&mut roots, std::path::Path::new(&path))?;
            }
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
            reqwest::Client::builder()
                .tls_backend_preconfigured(tls)
                .user_agent(concat!("UwUSync-Server/", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(TIMEOUT)
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// The certificates of a PEM file, as trusted roots.
fn add_roots(roots: &mut rustls::RootCertStore, path: &std::path::Path) -> Result<(), String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let what = || format!("{CA_VARIABLE} ({})", path.display());
    let mut added = 0;
    for certificate in
        CertificateDer::pem_file_iter(path).map_err(|error| format!("{}: {error}", what()))?
    {
        let certificate = certificate.map_err(|error| format!("{}: {error}", what()))?;
        roots
            .add(certificate)
            .map_err(|error| format!("{}: {error}", what()))?;
        added += 1;
    }
    if added == 0 {
        return Err(format!("{}: no certificate in it", what()));
    }
    Ok(())
}

/// What went wrong with a request, with the interesting part (a refused
/// connection, a certificate) that reqwest keeps in its sources.
pub fn error_text(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(inner) = source {
        let text = inner.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = inner.source();
    }
    message
}

/// A response's body, at most `max` bytes: refused at once when its length
/// says more, and stopped while reading when it sends more.
pub async fn read_limited(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max as u64)
    {
        return Err("answered with far too much".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error_text(&error))? {
        if body.len() + chunk.len() > max {
            return Err("answered with far too much".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The start of a response's body, at most `max` bytes; the rest is not read.
pub async fn read_start(mut response: reqwest::Response, max: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < max {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk[..chunk.len().min(max - body.len())]),
            _ => break,
        }
    }
    body
}

/// A response that is not a success, in words: the status, and an
/// OAuth-style `error` code when the body is JSON with one. Nothing else of
/// the body reaches a log line a person reads.
pub async fn refused(response: reqwest::Response) -> String {
    let status = response.status();
    if status.is_redirection() {
        return format!(
            "answered {status} and wants to send the request elsewhere, which is not followed"
        );
    }
    let body = read_start(response, ERROR_BYTES).await;
    let code = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .filter(|code| {
            (1..=40).contains(&code.len())
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        });
    match code {
        Some(code) => format!("answered {status} ({code})"),
        None => format!("answered {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn answers_are_read_up_to_a_ceiling() {
        let app = axum::Router::new()
            .route(
                "/long",
                axum::routing::get(|| async { vec![b'y'; 2 * 1024 * 1024] }),
            )
            .route("/short", axum::routing::get(|| async { "fine" }))
            .route(
                "/oauth",
                axum::routing::get(|| async {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        r#"{"error":"invalid_client","error_description":"inside"}"#,
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let get = |path: &str| client().unwrap().get(format!("{base}{path}")).send();

        let text = refused(get("/oauth").await.unwrap()).await;
        assert_eq!(text, "answered 400 Bad Request (invalid_client)");
        assert!(read_limited(get("/long").await.unwrap(), JSON_BYTES)
            .await
            .is_err());
        assert_eq!(
            read_limited(get("/short").await.unwrap(), JSON_BYTES)
                .await
                .unwrap(),
            b"fine"
        );
    }
}

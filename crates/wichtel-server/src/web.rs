//! Security headers, privacy-preserving request logging and static assets (Konzept §7.5).

use std::time::Instant;

use axum::body::Body;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};

/// Strict CSP: only same-origin resources; `'wasm-unsafe-eval'` for the WebAssembly module.
pub const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; manifest-src 'self'; \
    worker-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; \
    frame-ancestors 'none'";

const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
    magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()";

/// `Strict-Transport-Security` for deployments whose public URL is HTTPS (one year; no
/// `includeSubDomains`, other services of the operator may live on subdomains).
pub const HSTS: &str = "max-age=31536000";

/// Adds security headers to every response (`hsts`: public URL is HTTPS); API responses
/// additionally get `Cache-Control: no-store`.
pub async fn security_headers(State(hsts): State<bool>, req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    if hsts {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        );
    }
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    if is_api {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    } else if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    res
}

/// Request log without IP, user agent or path parameters: method, route template, status,
/// duration and a short hash tag of the `gid` (to correlate requests of one group).
pub async fn log_requests(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "<static>".to_owned());
    let tag = gid_tag(req.uri());
    let res = next.run(req).await;
    let status = res.status().as_u16();
    let ms = start.elapsed().as_millis() as u64;
    if res.status().is_server_error() {
        tracing::warn!(%method, route, status, ms, gid = tag.as_deref().unwrap_or("-"), "request");
    } else {
        tracing::debug!(%method, route, status, ms, gid = tag.as_deref().unwrap_or("-"), "request");
    }
    res
}

/// First 4 bytes (hex) of `H("wichtel/log" ‖ gid)` for `/api/groups/{gid}/…`.
pub fn gid_tag(uri: &Uri) -> Option<String> {
    let rest = uri.path().strip_prefix("/api/groups/")?;
    let gid = rest.split('/').next().filter(|s| !s.is_empty())?;
    let mut h = Sha256::new();
    h.update(b"wichtel/log");
    h.update(gid.as_bytes());
    let d = h.finalize();
    Some(d[..4].iter().map(|b| format!("{b:02x}")).collect())
}

/// The built web UI (`web/dist`). Missing at build time ⇒ empty, a placeholder page is served.
#[derive(RustEmbed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Assets;

const PLACEHOLDER: &str = "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Weihnachtswichtel</title></head><body><h1>Weihnachtswichtel</h1>\
<p>Die Web-Oberfläche wurde nicht mitgebaut (<code>web/dist</code> fehlt). \
Bitte <code>npm run build</code> in <code>web/</code> ausführen und den Server neu bauen.</p>\
</body></html>";

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn index() -> Response {
    match Assets::get("index.html") {
        Some(f) => file_response("index.html", f.data.into_owned()),
        None => file_response("index.html", PLACEHOLDER.as_bytes().to_vec()),
    }
}

fn file_response(path: &str, data: Vec<u8>) -> Response {
    let mut res = Response::new(Body::from(data));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(path)),
    );
    res
}

/// Static files with SPA fallback for `/` and `/g/{gid}`; unknown `/api/…` paths ⇒ JSON 404.
pub async fn static_handler(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return crate::error::ApiError::not_found().into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let rel = path.trim_start_matches('/');
    if rel.is_empty() || rel == "index.html" {
        return index();
    }
    if rel
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if let Some(f) = Assets::get(rel) {
        return file_response(rel, f.data.into_owned());
    }
    if rel == "g" || rel.starts_with("g/") {
        return index();
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_only_for_group_paths() {
        let t = gid_tag(&"/api/groups/AAAAAAAAAAAAAAAAAAAAAA/start".parse().unwrap()).unwrap();
        assert_eq!(t.len(), 8);
        assert!(!t.contains("AAAA"));
        assert_eq!(gid_tag(&"/api/health".parse().unwrap()), None);
        assert_eq!(gid_tag(&"/api/groups".parse().unwrap()), None);
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type("a/b.wasm"), "application/wasm");
        assert_eq!(content_type("app.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("x"), "application/octet-stream");
    }
}

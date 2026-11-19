//! The web UI (architecture doc §20, §21.3 E7): plain JavaScript and a
//! canvas, no build step. The files are compiled into the binary, so the
//! UI works with no network access and always matches the API it calls.

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

const INDEX: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const STYLE_CSS: &str = include_str!("../ui/style.css");
const ICON_SVG: &str = include_str!("../ui/icon.svg");

/// Scripts, styles and data from this server only; nothing inline.
const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; \
     frame-ancestors 'none'";

fn file(body: &'static str, content_type: &'static str) -> Response {
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    // The files change only with the binary; revalidating is cheap.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

pub(crate) async fn index() -> Response {
    let mut resp = file(INDEX, "text/html; charset=utf-8");
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(PAGE_CSP),
    );
    resp
}

pub(crate) async fn asset(Path(name): Path<String>) -> Response {
    match name.as_str() {
        "app.js" => file(APP_JS, "text/javascript; charset=utf-8"),
        "style.css" => file(STYLE_CSS, "text/css; charset=utf-8"),
        // Linked from the page, so browsers do not ask for /favicon.ico.
        "icon.svg" => file(ICON_SVG, "image/svg+xml"),
        _ => crate::error(StatusCode::NOT_FOUND, "no such file"),
    }
}

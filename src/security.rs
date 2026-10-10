use axum::{
    extract::{Request, State},
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{config::AppState, middleware::get_cookie_value};

#[derive(Clone)]
pub struct CsrfToken(pub String);

pub const CSRF_COOKIE: &str = "csrf_token";
pub const CSRF_ERROR: &str = "La sesión expiró. Recargá la pagina e intentá de nuevo";

pub async fn csrf_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let (token, is_new) = match get_cookie_value(req.headers(), CSRF_COOKIE) {
        Some(t) if !t.is_empty() => (t, false),
        _ => (Uuid::new_v4().simple().to_string(), true),
    };

    req.extensions_mut().insert(CsrfToken(token.clone()));
    let mut res = next.run(req).await;

    if is_new {
        let cookie = format!(
            "{CSRF_COOKIE}={token}; Path=/; SameSite=Strict; Max-Age=86400{}",
            secure_attr(state.cookie_secure)
        );

        if let Ok(value) = HeaderValue::from_str(&cookie) {
            res.headers_mut().append(header::SET_COOKIE, value);
        }
    }

    res
}

pub fn csrf_valid(expected: &CsrfToken, received: &str) -> bool {
    constant_time_eq(expected.0.as_bytes(), received.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || a.len() != b.len() {
        return false;
    }

    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn secure_attr(secure: bool) -> &'static str {
    if secure { "; Secure" } else { "" }
}

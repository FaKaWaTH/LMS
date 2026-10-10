use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use jsonwebtoken::{DecodingKey, Validation, decode};

use crate::{
    config::AppState,
    models::{Claims, User},
};

pub fn get_cookie_value(headers: &axum::http::HeaderMap, key: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            let mut parts = pair.trim().splitn(2, '=');
            let k = parts.next()?.trim();
            let v = parts.next()?.trim();

            if k == key { Some(v.to_string()) } else { None }
        })
}

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let token = match get_cookie_value(req.headers(), "lms_token") {
        Some(t) => t,
        None => return Err(Redirect::to("/login").into_response()),
    };

    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.jwt_secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(_) => return Err(Redirect::to("/login").into_response()),
    };

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(token_data.claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|_| Redirect::to("/login").into_response())?;

    req.extensions_mut().insert(user);

    Ok(next.run(req).await)
}

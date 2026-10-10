use axum::{
    Extension, Form,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Redirect},
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Deserialize;
use sqlx::error::ErrorKind;

use crate::{
    config::AppState,
    models::{Claims, Role, User},
    security::{CSRF_ERROR, CsrfToken, csrf_valid, secure_attr},
    templates::{LandingTemplate, LoginTemplate, RegisterTemplate},
};

pub async fn landing_page() -> impl IntoResponse {
    LandingTemplate
}

pub async fn login_page(Extension(csrf): Extension<CsrfToken>) -> impl IntoResponse {
    LoginTemplate {
        error_msg: None,
        csrf_token: csrf.0,
    }
}

pub async fn register_page(Extension(csrf): Extension<CsrfToken>) -> impl IntoResponse {
    RegisterTemplate {
        error_msg: None,
        csrf_token: csrf.0,
    }
}

#[derive(Deserialize)]
pub struct LoginPayload {
    email: String,
    password: String,
    #[serde(default)]
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct RegisterPayload {
    name: String,
    email: String,
    password: String,
    role: Option<String>,
    #[serde(default)]
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf_token: String,
}

fn validate_register(payload: &RegisterPayload) -> Option<String> {
    if payload.name.trim().is_empty() {
        return Some("Ingresá tu nombre completo".to_string());
    }

    if payload.email.trim().is_empty() || !payload.email.contains('@') {
        return Some("Ingresá un correo electrónico válido".to_string());
    }

    if payload.password.len() < 8 {
        return Some("La contraseña debe tener al menos 8 caracteres".to_string());
    }

    None
}

pub async fn register(
    State(state): State<AppState>,
    Extension(csrf): Extension<CsrfToken>,
    Form(payload): Form<RegisterPayload>,
) -> impl IntoResponse {
    if !csrf_valid(&csrf, &payload.csrf_token) {
        return RegisterTemplate {
            error_msg: Some(CSRF_ERROR.to_string()),
            csrf_token: csrf.0.clone(),
        }
        .into_response();
    }

    if let Some(msg) = validate_register(&payload) {
        return RegisterTemplate {
            error_msg: Some(msg),
            csrf_token: csrf.0.clone(),
        }
        .into_response();
    }

    let hashed = match hash(payload.password.as_bytes(), DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "fallo al hashear contraseña en registro");

            return RegisterTemplate {
                error_msg: Some("Error al procesar la contraseña".to_string()),
                csrf_token: csrf.0.clone(),
            }
            .into_response();
        }
    };

    let role = if payload.role.as_deref() == Some("teacher") {
        Role::Teacher
    } else {
        Role::Student
    };

    let res =
        sqlx::query("INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)")
            .bind(&payload.name)
            .bind(&payload.email.trim().to_lowercase())
            .bind(hashed)
            .bind(role)
            .execute(&state.db)
            .await;

    match res {
        Ok(_) => {
            tracing::info!(email = %payload.email, "nuevo usuario registrado");

            Redirect::to("/login").into_response()
        }
        Err(sqlx::Error::Database(db_err)) if db_err.kind() == ErrorKind::UniqueViolation => {
            RegisterTemplate {
                error_msg: Some("Ese correo ya esta registrado. Iniciá sesión".to_string()),
                csrf_token: csrf.0.clone(),
            }
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "error al registrar usuario");

            RegisterTemplate {
                error_msg: Some("Algo salió mal. Intentá de nuevo".to_string()),
                csrf_token: csrf.0.clone(),
            }
            .into_response()
        }
    }
}

pub async fn login(
    State(state): State<AppState>,
    Extension(csrf): Extension<CsrfToken>,
    Form(payload): Form<LoginPayload>,
) -> impl IntoResponse {
    if !csrf_valid(&csrf, &payload.csrf_token) {
        return RegisterTemplate {
            error_msg: Some(CSRF_ERROR.to_string()),
            csrf_token: csrf.0.clone(),
        }
        .into_response();
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT id, name, email, password_hash, role FROM users WHERE email = $1",
    )
    .bind(&payload.email.trim().to_lowercase())
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "error consultando usuario en login");

            return LoginTemplate {
                error_msg: Some("Algo salió mal. Intentá de nuevo".to_string()),
                csrf_token: csrf.0.clone(),
            }
            .into_response();
        }
    };

    if let Some(u) = user {
        if verify(&payload.password, &u.password_hash).unwrap_or(false) {
            let expiration = Utc::now()
                .checked_add_signed(Duration::hours(24))
                .expect("fecha válida")
                .timestamp() as u64;

            let claims = Claims {
                sub: u.id,
                role: u.role,
                exp: expiration,
            };

            if let Ok(token) = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
            ) {
                let cookie_header = format!(
                    "lms_token={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400{}",
                    secure_attr(state.cookie_secure)
                );

                tracing::info!(user_id = %u.id, "login exitoso");

                return (
                    [(header::SET_COOKIE, cookie_header)],
                    Redirect::to("/dashboard"),
                )
                    .into_response();
            }
        }
    }

    LoginTemplate {
        error_msg: Some("Correo o contraseña incorrectos".to_string()),
        csrf_token: csrf.0.clone(),
    }
    .into_response()
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(csrf): Extension<CsrfToken>,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    if !csrf_valid(&csrf, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Solicitud inválida").into_response();
    }

    let clear_cookie = format!(
        "lms_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        secure_attr(state.cookie_secure)
    );

    ([(header::SET_COOKIE, clear_cookie)], Redirect::to("/")).into_response()
}

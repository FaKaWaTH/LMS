use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    http::{HeaderValue, header},
    middleware::from_fn_with_state,
    routing::{get, post},
};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AppState;

pub mod config;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod security;
pub mod templates;

const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
    form-action 'self'; frame-ancestors 'none'; base-uri 'self'";

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

pub fn build_router(state: AppState) -> Router {
    let login_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(12)
            .burst_size(5)
            .finish()
            .expect("configuración de rate limit inválida"),
    );

    let register_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(3)
            .finish()
            .expect("configuración de rate limit inválida"),
    );

    let protected_routes = Router::new()
        .route("/dashboard", get(handlers::dashboard_router))
        .route_layer(from_fn_with_state(state.clone(), middleware::require_auth));

    Router::new()
        .route("/", get(handlers::landing_page))
        .route("/login", get(handlers::login_page))
        .route(
            "/login",
            post(handlers::login).route_layer(GovernorLayer::new(login_limit)),
        )
        .route("/register", get(handlers::register_page))
        .route(
            "/register",
            post(handlers::register).route_layer(GovernorLayer::new(register_limit)),
        )
        .route("/logout", post(handlers::logout))
        .merge(protected_routes)
        .layer(from_fn_with_state(state.clone(), security::csrf_middleware))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let state = config::get_state().await;

    tracing::info!("Migrando DB...");
    sqlx::migrate!("./migrations").run(&state.db).await?;
    tracing::info!("DB sincronizada");

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Servidor LMS iniciado en http://localhost:3000");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

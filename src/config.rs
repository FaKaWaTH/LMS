use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
    pub cookie_secure: bool,
}

pub async fn get_state() -> AppState {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://lms_user:lms_password@localhost:5432/lms_dev".to_string());

    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev_key".to_string());

    let cookie_secure = std::env::var("COOKIE_SECURE")
        .map(|v| v == "true")
        .unwrap_or(false);

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Could not connect to db");

    AppState {
        db: pool,
        jwt_secret,
        cookie_secure,
    }
}

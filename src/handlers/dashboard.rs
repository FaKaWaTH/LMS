use axum::{Extension, response::IntoResponse};

use crate::{
    models::{Role, User},
    security::CsrfToken,
    templates::{DashboardStudentTemplate, DashboardTeacherTemplate},
};

pub async fn dashboard_router(
    Extension(user): Extension<User>,
    Extension(csrf): Extension<CsrfToken>,
) -> impl IntoResponse {
    let name = display_name(&user);
    let initials = initials(&name);

    match user.role {
        Role::Student => DashboardStudentTemplate {
            user_name: name,
            initials,
            csrf_token: csrf.0,
        }
        .into_response(),

        Role::Teacher => DashboardTeacherTemplate {
            user_name: name,
            initials,
            csrf_token: csrf.0,
        }
        .into_response(),
    }
}

fn display_name(user: &User) -> String {
    if user.name.trim().is_empty() {
        user.email
            .split('@')
            .next()
            .unwrap_or("usuario")
            .to_string()
    } else {
        user.name.clone()
    }
}

fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

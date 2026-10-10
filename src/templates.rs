use askama::Template;
use askama_web::WebTemplate;

#[derive(Template, WebTemplate)]
#[template(path = "../templates/landing.html")]
pub struct LandingTemplate;

#[derive(Template, WebTemplate)]
#[template(path = "../templates/register.html")]
pub struct RegisterTemplate {
    pub error_msg: Option<String>,
    pub csrf_token: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "../templates/login.html")]
pub struct LoginTemplate {
    pub error_msg: Option<String>,
    pub csrf_token: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "../templates/dashboard_teacher.html")]
pub struct DashboardTeacherTemplate {
    pub user_name: String,
    pub initials: String,
    pub csrf_token: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "../templates/dashboard_student.html")]
pub struct DashboardStudentTemplate {
    pub user_name: String,
    pub initials: String,
    pub csrf_token: String,
}

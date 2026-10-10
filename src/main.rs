#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    lms::init_tracing();
    lms::run().await
}

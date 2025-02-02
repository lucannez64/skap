mod postgres;
mod protocol;
mod server;

use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    server::run().await?;
    Ok(())
}

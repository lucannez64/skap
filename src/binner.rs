#![recursion_limit = "256"]
mod postgres;
mod protocol;
mod server;
mod redis;

use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    server::run().await?;
    Ok(())
}

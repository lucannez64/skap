#![recursion_limit = "256"]
mod postgres;
mod protocol;
mod redis;
mod security;
mod server;

use dotenvy::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    server::run().await?;
    Ok(())
}

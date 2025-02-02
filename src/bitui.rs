mod client;
mod protocol;
mod tui;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tui::run_tui().await?;
    Ok(())
}

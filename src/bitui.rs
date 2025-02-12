use protocol::ClientEx;

mod client;
mod protocol;
mod tui;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ClientEx::from_file("/run/media/hirew/SECURED/client1".to_string())?;
    let di = client.c.di_q.to_di();
    println!("{:?}", di.bytes.len());
    // tui::run_tui().await?;
    Ok(())
}

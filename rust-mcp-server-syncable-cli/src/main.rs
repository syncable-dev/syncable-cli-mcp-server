// src/main.rs
use rust-mcp-server-syncable-cli::start_stdio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_stdio().await?;
    Ok(())
}

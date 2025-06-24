// src/main.rs
use rust_mcp_server_syncable_cli::start_stdio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_stdio().await?;
    Ok(())
}

// src/main_sse.rs
use rust_mcp_server_syncable_cli::start_sse;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_sse().await?;
    Ok(())
}

// src/main.rs
use mcp_rust_server::start_stdio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_stdio().await?;
    Ok(())
}

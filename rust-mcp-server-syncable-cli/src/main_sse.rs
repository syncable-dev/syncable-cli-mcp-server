// src/main_sse.rs
use mcp_rust_server::start_sse;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_sse().await?;
    Ok(())
}

// src/main_sse.rs

mod handler;
mod tools;

use handler::MyServerHandler;
use rust_mcp_sdk::{
    error::SdkResult,
    mcp_server::{hyper_server, HyperServerOptions},
    McpServer,
    schema::{
        Implementation, InitializeResult, ServerCapabilities, ServerCapabilitiesTools,
        LATEST_PROTOCOL_VERSION,
    },
};
// Import the necessary components for tracing
use tracing_subscriber::{prelude::*, EnvFilter, fmt};

#[tokio::main]
async fn main() -> SdkResult<()> {
    // Correctly initialize the tracing subscriber using layers.
    // This allows combining the formatting layer with an environment filter.
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    tracing::info!("Logger initialized. Defining server details...");

    // Define server details for the SSE server
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "Rust Map Server (SSE)".to_string(),
            version: "0.1.0".to_string(),
        },
        capabilities: ServerCapabilities {
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            ..Default::default()
        },
        protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
        instructions: Some("Welcome to the Rust Map Server (SSE). Connect via a web client.".into()),
        meta: None,
    };

    tracing::info!("Instantiating custom server handler...");
    let handler = MyServerHandler {};

    tracing::info!("Configuring Hyper server options...");
    // Initialize options. The `server_error_hook` field does not exist in this SDK version.
    let options = HyperServerOptions {
        host: "0.0.0.0".to_string(),
        port: 8000,
        ..Default::default()
    };

    tracing::info!("Creating the MCP hyper_server instance...");
    // Pass options by value (move), not by clone.
    let server = hyper_server::create_server(server_details, handler, options);

    tracing::info!(
        "Starting Rust Map Server (SSE) on http://0.0.0.0:8000"
    );

    // Start the server and log any potential errors.
    if let Err(e) = server.start().await {
        tracing::error!(error = %e, "Server failed to start");
    }

    Ok(())
}

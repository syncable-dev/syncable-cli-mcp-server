// src/main.rs

mod handler;
mod tools;

use handler::MyServerHandler;
use rust_mcp_sdk::{
    error::SdkResult,
    mcp_server::{server_runtime, ServerRuntime},
    // Import the McpServer trait to bring the .start() method into scope
    McpServer,
    schema::{
        Implementation, InitializeResult, ServerCapabilities, ServerCapabilitiesTools,
        LATEST_PROTOCOL_VERSION,
    },
    StdioTransport, TransportOptions,
};

#[tokio::main]
async fn main() -> SdkResult<()> {
    // Define server details and capabilities
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "Rust Map Server".to_string(),
            version: "0.1.0".to_string(),
        },
        capabilities: ServerCapabilities {
            // This server supports tools
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            ..Default::default()
        },
        protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
        instructions: Some("Welcome to the Rust Map Server. Use list_tools to see available functionalities.".into()),
        meta: None,
    };

    // Create a stdio transport with default options
    let transport = StdioTransport::new(TransportOptions::default())?;

    // Instantiate our custom handler
    let handler = MyServerHandler {};

    // Create the MCP server runtime
    let server: ServerRuntime = server_runtime::create_server(server_details, transport, handler);

    println!("Starting Rust Map Server...");

    // Start the server
    server.start().await
}

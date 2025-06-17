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
use tools::ServerTools;

#[tokio::main]
async fn main() -> SdkResult<()> {
    // Initialize basic logging
    env_logger::init();
    
    // Define server details and capabilities
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "Syncable-MCP-Server".to_string(),
            version: "0.1.0".to_string(),
        },
        capabilities: ServerCapabilities {
            // This server supports tools
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            ..Default::default()
        },
        protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
        instructions: Some("Welcome to the Syncable-MCP-Server. Use list_tools to see available functionalities.".into()),
        meta: None,
    };

    // Log available tools on startup
    let available_tools = ServerTools::tools();
    println!("🚀 Starting Syncable-MCP-Server...");
    println!("📋 Available tools ({}):", available_tools.len());
    for (i, tool) in available_tools.iter().enumerate() {
        println!("   {}. {} - {}", 
                 i + 1, 
                 tool.name, 
                 tool.description.as_deref().unwrap_or("No description"));
    }
    println!();

    // Create a stdio transport with default options
    let transport = StdioTransport::new(TransportOptions::default())?;

    // Instantiate our custom handler
    let handler = MyServerHandler {};

    // Create the MCP server runtime
    let server: ServerRuntime = server_runtime::create_server(server_details, transport, handler);

    println!("✅ Server initialized successfully. Listening for MCP requests...");

    // Start the server
    server.start().await
}

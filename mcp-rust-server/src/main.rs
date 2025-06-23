// src/main.rs

mod handler;
mod tools;

use handler::MyServerHandler;
use rust_mcp_sdk::{
    error::SdkResult,
    mcp_server::{server_runtime, ServerRuntime},
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
    // 1) Init logging
    env_logger::init();

    // 2) Build our initialize result
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "Syncable-MCP-Server".to_string(),
            version: "0.1.0".to_string(),
        },
        capabilities: ServerCapabilities {
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            ..Default::default()
        },
        protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
        instructions: Some(
            "Welcome to the Syncable-MCP-Server. Use list_tools to see available functionalities."
                .into(),
        ),
        meta: None,
    };

    // 3) Log banners *to stderr* only
    let available_tools = ServerTools::tools();
    eprintln!("🚀 Starting Syncable-MCP-Server (stdio mode)...");
    eprintln!("📋 Available tools ({}):", available_tools.len());
    for (i, tool) in available_tools.iter().enumerate() {
        eprintln!(
            "   {}. {} - {}",
            i + 1,
            tool.name,
            tool.description.as_deref().unwrap_or("No description")
        );
    }
    eprintln!();
    eprintln!("✅ Server initialized successfully. Listening for MCP requests...");

    // 4) Create the stdio transport and server runtime
    let transport = StdioTransport::new(TransportOptions::default())?;
    let handler = MyServerHandler {};
    let server: ServerRuntime =
        server_runtime::create_server(server_details, transport, handler);

    // 5) Hand off to the SDK’s dispatcher; it will read framed requests from stdin
    //    and write framed responses to stdout (flushing each one).
    server.start().await
}

mod handler;
mod tools;

use handler::MyServerHandler;
use rust_mcp_sdk::{
    error::SdkResult,
    mcp_server::{hyper_server, server_runtime, HyperServerOptions, ServerRuntime},
    schema::{
        Implementation, InitializeResult, ServerCapabilities, ServerCapabilitiesTools,
        LATEST_PROTOCOL_VERSION,
    },
    McpServer, StdioTransport, TransportOptions,
};
use tools::ServerTools;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub async fn start_stdio() -> SdkResult<()> {
    // 1) Init logging
    env_logger::init();

    // 2) Build initialize result
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "Syncable-MCP-Server".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
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

    // 3) Log banners to stderr
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

    // 4) Create transport and runtime
    let transport = StdioTransport::new(TransportOptions::default())?;
    let handler = MyServerHandler {};
    let server: ServerRuntime = server_runtime::create_server(server_details, transport, handler);

    // 5) Run
    server.start().await?;
    Ok(())
}

pub async fn start_sse() -> SdkResult<()> {
    // 1) Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    tracing::info!("Logger initialized. Defining server details...");

    // 2) Build initialize result
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "Rust MCP Server (SSE)".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        capabilities: ServerCapabilities {
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            ..Default::default()
        },
        protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
        instructions: Some(
            "Welcome to the Rust MCP Server (SSE). Connect via a web client.".into(),
        ),
        meta: None,
    };

    // 3) Log tools
    let available_tools = ServerTools::tools();
    tracing::info!("🚀 Starting Rust MCP Server (SSE)...");
    tracing::info!("📋 Available tools ({}):", available_tools.len());
    for (i, tool) in available_tools.iter().enumerate() {
        tracing::info!(
            "   {}. {} - {}",
            i + 1,
            tool.name,
            tool.description.as_deref().unwrap_or("No description")
        );
    }

    // 4) Create handler & server options
    let handler = MyServerHandler {};
    let options = HyperServerOptions {
        host: "0.0.0.0".to_string(),
        port: 8000,
        ..Default::default()
    };

    tracing::info!("Creating the MCP SSE server...");
    let server = hyper_server::create_server(server_details, handler, options);

    tracing::info!("✅ SSE server listening on http://0.0.0.0:8000");
    // 5) Run
    server.start().await?;
    Ok(())
}

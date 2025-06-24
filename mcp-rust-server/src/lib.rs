//! # mcp_rust_server
//!
//! High-performance Model Context Protocol (MCP) server for code analysis, security scanning,
//! and project insights.
//!
//! ## Features
//!
//! - **Fast & Scalable**: async Rust on Tokio runtime  
//! - **Protocols**: stdio and SSE (Server-Sent Events) transports  
//! - **Extensible**: easy to add new handlers and endpoints  
//! - **Production-Ready**: optimized release profile and structured logging  
//!
//! ## Installation
//!
//! **As a library**  
//! Add to your `Cargo.toml` dependencies:
//! ```toml
//! [dependencies]
//! mcp-rust-server = "0.1.0"
//! ```
//!
//! **As CLI binaries**  
//! Install from crates.io with Cargo:
//! ```bash
//! cargo install mcp-rust-server
//! ```
//! Binaries (`mcp-stdio` and `mcp-sse`) are placed in `$CARGO_HOME/bin`.
//!
//! ## Usage
//!
//! ### Library
//!  
//! ```rust
//! use mcp_rust_server::{start_stdio, start_sse};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Run as stdio MCP server
//!     start_stdio().await?;
//!
//!     // Or run as SSE MCP server
//!     // start_sse().await?;
//!     Ok(())
//! }
//! ```
//!
//! ### CLI
//!  
//! ```bash
//! # Start stdio server
//! mcp-stdio
//!
//! # Start SSE server
//! mcp-sse
//! ```
//!
//! ## Examples
//!  
//! See each function’s docs below for more examples.

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

/// Starts the MCP server in **stdio** mode.
///
/// Reads framed MCP requests from `stdin` and writes framed responses to `stdout`.
///
/// # Errors
///
/// Returns an `SdkResult` error if initialization or transport setup fails.
///
/// # Example
///
/// ```no_run
/// use mcp_rust_server::start_stdio;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     start_stdio().await?;
///     Ok(())
/// }
/// ```
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

/// Starts the MCP server in **SSE** (Server-Sent Events) mode.
///
/// Hosts an HTTP endpoint on `http://0.0.0.0:8000/mcp` that streams MCP responses.
///
/// # Errors
///
/// Returns an `SdkResult` error if the HTTP server fails to bind or run.
///
/// # Example
///
/// ```no_run
/// use mcp_rust_server::start_sse;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     start_sse().await?;
///     Ok(())
/// }
/// ```
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

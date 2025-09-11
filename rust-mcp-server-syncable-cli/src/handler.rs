// src/handler.rs

use async_trait::async_trait;
use rust_mcp_sdk::schema::{
    schema_utils::CallToolError, CallToolRequest, CallToolResult, ListToolsRequest,
    ListToolsResult, RpcError,
};
use rust_mcp_sdk::{mcp_server::ServerHandler, McpServer};

use crate::tools::ServerTools;

// Custom Handler to handle MCP Messages
pub struct MyServerHandler;

#[async_trait]
impl ServerHandler for MyServerHandler {
    // Handle ListToolsRequest, return list of available tools as ListToolsResult
    async fn handle_list_tools_request(
        &self,
        _request: ListToolsRequest,
        _runtime: &dyn McpServer,
    ) -> std::result::Result<ListToolsResult, RpcError> {
        Ok(ListToolsResult {
            tools: ServerTools::tools(),
            meta: None,
            next_cursor: None,
        })
    }

    /// Handles incoming CallToolRequest and processes it using the appropriate tool.
    async fn handle_call_tool_request(
        &self,
        request: CallToolRequest,
        _runtime: &dyn McpServer,
    ) -> std::result::Result<CallToolResult, CallToolError> {
        // Attempt to convert request parameters into the ServerTools enum
        let tool_call: ServerTools =
            ServerTools::try_from(request.params).map_err(CallToolError::new)?;

        // Match on the specific tool variant and execute its logic
        match tool_call {
            ServerTools::AboutInfoTool(tool) => tool.call_tool(),
            ServerTools::AnalysisScanTool(tool) => tool.call_tool().await,
            ServerTools::SecurityScanTool(tool) => tool.call_tool(),
            ServerTools::DependencyScanTool(tool) => tool.call_tool().await,
        }
    }
}
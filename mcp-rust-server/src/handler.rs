// src/handler.rs

use async_trait::async_trait;
use rust_mcp_sdk::{
    mcp_server::ServerHandler, // ServerHandler is in the mcp_server module
    McpServer,                 // McpServer trait is at the crate root
    schema::{
        schema_utils::CallToolError, CallToolRequest, CallToolResult, ListToolsRequest,
        ListToolsResult, RpcError,
    },
};
use crate::tools::ServerTools; // Import our generated tool enum

pub struct MyServerHandler;

#[async_trait]
impl ServerHandler for MyServerHandler {
    /// Handles the request to list all available tools.
    async fn handle_list_tools_request(
        &self,
        _request: ListToolsRequest,
        _runtime: &dyn McpServer, // This now resolves correctly
    ) -> Result<ListToolsResult, RpcError> {
        Ok(ListToolsResult {
            tools: ServerTools::tools(), // Use the 'tools()' method from our tool_box
            meta: None,
            next_cursor: None,
        })
    }

    /// Handles a request to call a specific tool by name.
    async fn handle_call_tool_request(
        &self,
        request: CallToolRequest,
        _runtime: &dyn McpServer, // This now resolves correctly
    ) -> Result<CallToolResult, CallToolError> {
        // Deserialize the request parameters into our ServerTools enum
        let tool_call: ServerTools =
            ServerTools::try_from(request.params).map_err(CallToolError::new)?;

        // Match on the specific tool variant and execute its logic
        match tool_call {
            ServerTools::AddTool(tool) => tool.call_tool(),
            ServerTools::MultiplyTool(tool) => tool.call_tool(),
            ServerTools::ReverseTool(tool) => tool.call_tool(),
            ServerTools::AboutInfoTool(tool) => tool.call_tool(),
            ServerTools::GreetingTool(tool) => tool.call_tool(),
            ServerTools::SummarizeTool(tool) => tool.call_tool(),
        }
    }
}

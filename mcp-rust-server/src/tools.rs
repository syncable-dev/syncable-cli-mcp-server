// src/tools.rs

use rust_mcp_sdk::schema::{schema_utils::CallToolError, CallToolResult};
use rust_mcp_sdk::{
    macros::{mcp_tool, JsonSchema},
    tool_box,
};
use std::path::Path;
use syncable_cli;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct AnalyzeToolError(String);

impl fmt::Display for AnalyzeToolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for AnalyzeToolError {}

// --- Tool to act as the "info" resource ---
#[mcp_tool(
    name = "about_info",
    description = "Provides information about this demo MCP server."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct AboutInfoTool {}

impl AboutInfoTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let info = "This is a demo MCP server with tools and resources.".to_string();
        Ok(CallToolResult::text_content(info, None))
    }
}

// --- Tool for analyzing a project ---
#[mcp_tool(
    name = "analyzeProject",
    description = "Analyzes a project at a given path and returns a JSON report. Defaults to the current directory if no path is provided."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct AnalyzeProjectTool {
    /// The path to the project to analyze. Defaults to the current directory.
    path: Option<String>,
}

impl AnalyzeProjectTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let project_path_str = self.path.as_deref().unwrap_or(".");
        let analysis_result = syncable_cli::analyzer::analyze_project(Path::new(project_path_str));
        match analysis_result {
            Ok(analysis) => {
                let json_output = serde_json::to_string_pretty(&analysis).unwrap_or_else(|e| {
                    format!("{{\"error\": \"Failed to serialize analysis result: {}\"}}", e)
                });
                Ok(CallToolResult::text_content(json_output, None))
            }
            Err(e) => {
                let error_message = format!("Failed to analyze project: {}", e);
                Err(CallToolError::new(AnalyzeToolError(error_message)))
            }
        }
    }
}

// --- Create a Tool Box ---
// This generates an enum `ServerTools` that contains all our defined tools.
tool_box!(ServerTools, [
    AboutInfoTool,
    AnalyzeProjectTool
]);

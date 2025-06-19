// src/tools.rs

use rust_mcp_sdk::schema::{schema_utils::CallToolError, CallToolResult};
use rust_mcp_sdk::{
    macros::{mcp_tool, JsonSchema},
    tool_box,
};
use syncable_cli::cli::{DisplayFormat::Matrix, DisplayFormat::Detailed, DisplayFormat::Summary};
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
    name = "analyze_project",
    description = "Analyzes a project at a given path and returns a JSON report. Defaults to the current directory if no path is provided."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct AnalyzeProjectTool {
    /// The path to the project to analyze. Defaults to the current directory.
    path: Option<String>,
    display: Option<String>,
}

impl AnalyzeProjectTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let project_path_str = self.path.as_deref().unwrap_or(".");
        let display = self.display.clone().unwrap_or("matrix".to_string());

        let display_format = match display.as_str() {
            "matrix" => Some(Matrix),
            "detailed" => Some(Detailed),
            "summary" => Some(Summary),
            _ => None,
        };

        println!("🔍 Analyzing project: {}", project_path_str);
        println!("🔍 Display: {}", display);

        let analysis_result = syncable_cli::handle_analyze(Path::new(project_path_str).to_path_buf(), false, false, display_format, None);
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

#[mcp_tool(
    name = "security_scan",
    description = "Scans a project for security vulnerabilities and secret leaks."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct SecurityScanTool {
    path: Option<String>,
}

impl SecurityScanTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let project_path_str = self.path.as_deref().unwrap_or(".");
        let security_results = syncable_cli::handle_security(Path::new(project_path_str).to_path_buf(), syncable_cli::cli::SecurityScanMode::Balanced, false, false, false, false, false, vec![], syncable_cli::cli::OutputFormat::Table, None, false);
        match security_results {
            Ok(analysis) => {
                let json_output = serde_json::to_string_pretty(&analysis).unwrap_or_else(|e| {
                    format!("{{\"error\": \"Failed to serialize analysis result: {}\"}}", e)
                });
                Ok(CallToolResult::text_content(json_output, None))
            }
            Err(e) => {
                let error_message = format!("Failed to analyze project for security: {}", e);
                Err(CallToolError::new(AnalyzeToolError(error_message)))
            }
        }
    }
}

#[mcp_tool(
    name = "dependency_scan",
    description = "Scans a project for dependencies and their vulnerabilities. Defaults to the current directory if no path is provided."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct DependencyScanTool {
    path: Option<String>,
}

impl  DependencyScanTool {
    pub async fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let project_path_str = self.path.as_deref().unwrap_or(".");
        let dependency_results = syncable_cli::handle_dependencies(Path::new(project_path_str).to_path_buf(),false, false, false, false, syncable_cli::cli::OutputFormat::Table).await;
        match dependency_results {
            Ok(output) => {
                let json_output = serde_json::to_string_pretty(&output).unwrap_or_else(|e| {
                    format!("{{\"error\": \"Failed to serialize analysis result: {}\"}}", e)
                });
                Ok(CallToolResult::text_content(json_output, None))
            }
            Err(e) => {
                let error_message = format!("Failed to analyze project for dependencies: {}", e);
                Err(CallToolError::new(AnalyzeToolError(error_message)))
            }
        }
    }
}

// --- Create a Tool Box ---
// This generates an enum `ServerTools` that contains all our defined tools.
tool_box!(ServerTools, [
    AboutInfoTool,
    AnalyzeProjectTool,
    SecurityScanTool,
    DependencyScanTool
]);

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

// --- Tool for adding two numbers ---
#[mcp_tool(
    name = "add",
    description = "Calculates the sum of two integers."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct AddTool {
    /// The first number.
    a: i64,
    /// The second number.
    b: i64,
}

impl AddTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let result = self.a + self.b;
        // Convert the numerical result to a string and use text_content
        Ok(CallToolResult::text_content(result.to_string(), None))
    }
}

// --- Tool for multiplying two numbers ---
#[mcp_tool(
    name = "multiply",
    description = "Calculates the product of two integers."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct MultiplyTool {
    /// The first number.
    a: i64,
    /// The second number.
    b: i64,
}

impl MultiplyTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let result = self.a * self.b;
        // Convert the numerical result to a string and use text_content
        Ok(CallToolResult::text_content(result.to_string(), None))
    }
}

// --- Tool for reversing a string ---
#[mcp_tool(
    name = "reverse",
    description = "Reverses the characters of a given string."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct ReverseTool {
    /// The text to reverse.
    text: String,
}

impl ReverseTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let reversed_text = self.text.chars().rev().collect::<String>();
        Ok(CallToolResult::text_content(reversed_text, None))
    }
}

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

// --- Tool to act as the "greeting" resource ---
#[mcp_tool(
    name = "greeting",
    description = "Generates a personalized greeting."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct GreetingTool {
    /// The name of the person to greet.
    name: String,
}

impl GreetingTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let greeting = format!("Hello, {}!", self.name);
        Ok(CallToolResult::text_content(greeting, None))
    }
}

// --- Tool to act as the "summarize" prompt ---
#[mcp_tool(
    name = "summarize",
    description = "Creates a short summary of the given text."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct SummarizeTool {
    /// The text to summarize.
    text: String,
}

impl SummarizeTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let summary = if self.text.len() > 20 {
            format!("Summary: {}...", &self.text[..20])
        } else {
            format!("Summary: {}", self.text)
        };
        Ok(CallToolResult::text_content(summary, None))
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
    AddTool,
    MultiplyTool,
    ReverseTool,
    AboutInfoTool,
    GreetingTool,
    SummarizeTool,
    AnalyzeProjectTool
]);

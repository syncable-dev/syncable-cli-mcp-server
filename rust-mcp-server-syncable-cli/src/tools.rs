// src/tools.rs

use rust_mcp_sdk::schema::{schema_utils::CallToolError, CallToolResult, TextContent};
use rust_mcp_sdk::{
    macros::{mcp_tool, JsonSchema},
    tool_box,
};
use std::error::Error;
use std::fmt;
use std::path::Path;
//use syncable_cli;
use syncable_cli::cli::{DisplayFormat::Detailed, DisplayFormat::Matrix, DisplayFormat::Summary};

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
    description = "Provides a detailed overview of this MCP server's capabilities, which include code analysis, security scanning, and dependency checking."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct AboutInfoTool {}

impl AboutInfoTool {
    pub fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        const BOLD: &str = "\x1B[1m";
        const YELLOW: &str = "\x1B[33m";
        const MAGENTA: &str = "\x1B[35m";
        const CYAN: &str = "\x1B[36m";
        const GREEN: &str = "\x1B[32m";
        const RESET: &str = "\x1B[0m";

        let info = format!(
            "\n{BOLD}{MAGENTA}Welcome to the Syncable CLI MCP Server!{RESET}\n\n\
            This server provides a powerful suite of tools to analyze your codebase directly from your AI assistant. \
            You can perform comprehensive scans for code structure, security vulnerabilities, and dependency issues.\n\n\
            {BOLD}{YELLOW}Here are the primary tools available:{RESET}\n\n\
            {BOLD}1. Analysis Scan (analysis_scan):{RESET}\n\
            \t{BOLD}What it does{RESET}: Performs a deep analysis of your project to identify languages, frameworks, architecture patterns, and more.\n\
            \t{BOLD}How to use{RESET}: Call the tool with a {CYAN}path{RESET} to your project.\n\
            \t{BOLD}Customization{RESET}: You can control the output format using the {CYAN}display{RESET} argument with options like {GREEN}\"matrix\"{RESET} (default), {GREEN}\"detailed\"{RESET}, or {GREEN}\"summary\"{RESET}.\n\n\
            {BOLD}2. Security Scan (security_scan):{RESET}\n\
            \t{BOLD}What it does{RESET}: Scans your codebase for security risks, including exposed secrets and common vulnerabilities.\n\
            \t{BOLD}How to use{RESET}: Provide the {CYAN}path{RESET} to the project you want to scan.\n\
            \t{BOLD}Customization{RESET}: Uses a balanced scan mode by default. Other modes like {GREEN}'lightning'{RESET} or {GREEN}'paranoid'{RESET} will be available.\n\n\
            {BOLD}3. Dependency Scan (dependency_scan):{RESET}\n\
            \t{BOLD}What it does{RESET}: Inspects your project's dependencies and checks them against known vulnerability databases.\n\
            \t{BOLD}How to use{RESET}: Specify the project {CYAN}path{RESET} to scan for dependencies.\n\
            \t{BOLD}Customization{RESET}: You can add arguments to check for licenses or filter vulnerabilities by severity level.\n\n\
            This server empowers you to maintain high standards of code quality, security, and dependency management with simple, powerful commands.\n"
        );
        Ok(CallToolResult::text_content(vec![TextContent::new(info, None, None)]))
    }
}

// --- Tool for analyzing a project ---
#[mcp_tool(
    name = "analysis_scan",
    description = "Analyzes a project at a given path and returns a JSON report. Defaults to the current directory if no path is provided."
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct AnalysisScanTool {
    /// The path to the project to analyze. Defaults to the current directory.
    path: Option<String>,
    display: Option<String>,
}

impl AnalysisScanTool {
    pub async fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let project_path_str = self.path.as_deref().unwrap_or(".");
        let display = self.display.clone().unwrap_or("matrix".to_string());

        let display_format = match display.as_str() {
            "matrix" => Some(Matrix),
            "detailed" => Some(Detailed),
            "summary" => Some(Summary),
            _ => None,
        };

        // Log to stderr so we don't interfere with MCP stdout JSON messages
        eprintln!("🔍 Analyzing project: {}", project_path_str);
        eprintln!("🔍 Display: {}", display);
        eprintln!("➡️  Calling syncable_cli::handle_analyze...");

        let analysis_result = tokio::task::spawn_blocking({
            let project_path = Path::new(project_path_str).to_path_buf();
            move || {
                syncable_cli::handle_analyze(
                    project_path,
                    true,
                    false,
                    display_format,
                    None,
                    None,
                )
            }
        }).await;

        let analysis_result = match analysis_result {
            Ok(result) => result,
            Err(e) => return Err(CallToolError::new(AnalyzeToolError(format!("Task panicked: {}", e)))),
        };
        match analysis_result {
            Ok(analysis_json_str) => {
                eprintln!("✅ handle_analyze returned ({} bytes)", analysis_json_str.len());
                
                // Validate JSON to ensure it's well-formed
                match serde_json::from_str::<serde_json::Value>(&analysis_json_str) {
                    Ok(_) => {
                        eprintln!("✅ JSON validation passed");
                        eprintln!("📤 Sending full response ({} bytes)", analysis_json_str.len());
                        Ok(CallToolResult::text_content(vec![TextContent::new(analysis_json_str, None, None)]))
                    }
                    Err(e) => {
                        eprintln!("⚠️  JSON validation failed: {}", e);
                        eprintln!("First 500 chars: {}", &analysis_json_str[..std::cmp::min(500, analysis_json_str.len())]);
                        return Err(CallToolError::new(AnalyzeToolError(format!("Invalid JSON response: {}", e))));
                    }
                }
            }
            Err(e) => {
                let error_message = format!("Failed to analyze project: {}", e);
                eprintln!("❌ handle_analyze error: {}", &error_message);
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
        
        // Log to stderr so we don't interfere with MCP stdout JSON messages
        eprintln!("🔒 Scanning project for security: {}", project_path_str);
        eprintln!("➡️  Calling syncable_cli::handle_security...");
        
        let security_results = syncable_cli::handle_security(
            Path::new(project_path_str).to_path_buf(),
            syncable_cli::cli::SecurityScanMode::Balanced,
            false,
            false,
            false,
            false,
            false,
            vec![],
            syncable_cli::cli::OutputFormat::Json,
            None,
            false,
        );
        match security_results {
            Ok(analysis) => {
                let json_output = serde_json::to_string_pretty(&analysis).unwrap_or_else(|e| {
                    format!(
                        "{{\"error\": \"Failed to serialize analysis result: {}\"}}",
                        e
                    )
                });
                
                eprintln!("✅ handle_security returned ({} bytes)", json_output.len());
                
                // Validate JSON to ensure it's well-formed
                match serde_json::from_str::<serde_json::Value>(&json_output) {
                    Ok(_) => {
                        eprintln!("✅ JSON validation passed");
                        eprintln!("📤 Sending full response ({} bytes)", json_output.len());
                        Ok(CallToolResult::text_content(vec![TextContent::new(json_output, None, None)]))
                    }
                    Err(e) => {
                        eprintln!("⚠️  JSON validation failed: {}", e);
                        eprintln!("First 500 chars: {}", &json_output[..std::cmp::min(500, json_output.len())]);
                        return Err(CallToolError::new(AnalyzeToolError(format!("Invalid JSON response: {}", e))));
                    }
                }
            }
            Err(e) => {
                let error_message = format!("Failed to analyze project for security: {}", e);
                eprintln!("❌ handle_security error: {}", &error_message);
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

impl DependencyScanTool {
    pub async fn call_tool(&self) -> Result<CallToolResult, CallToolError> {
        let project_path_str = self.path.as_deref().unwrap_or(".");
        
        // Log to stderr so we don't interfere with MCP stdout JSON messages
        eprintln!("📦 Scanning project for dependencies: {}", project_path_str);
        eprintln!("➡️  Calling syncable_cli::handle_dependencies...");
        
        let dependency_results = syncable_cli::handle_dependencies(
            Path::new(project_path_str).to_path_buf(),
            false,
            false,
            false,
            false,
            syncable_cli::cli::OutputFormat::Json,
        )
        .await;
        match dependency_results {
            Ok(output) => {
                let json_output = serde_json::to_string_pretty(&output).unwrap_or_else(|e| {
                    format!(
                        "{{\"error\": \"Failed to serialize analysis result: {}\"}}",
                        e
                    )
                });
                
                eprintln!("✅ handle_dependencies returned ({} bytes)", json_output.len());
                
                // Validate JSON to ensure it's well-formed
                match serde_json::from_str::<serde_json::Value>(&json_output) {
                    Ok(_) => {
                        eprintln!("✅ JSON validation passed");
                        eprintln!("📤 Sending full response ({} bytes)", json_output.len());
                        Ok(CallToolResult::text_content(vec![TextContent::new(json_output, None, None)]))
                    }
                    Err(e) => {
                        eprintln!("⚠️  JSON validation failed: {}", e);
                        eprintln!("First 500 chars: {}", &json_output[..std::cmp::min(500, json_output.len())]);
                        return Err(CallToolError::new(AnalyzeToolError(format!("Invalid JSON response: {}", e))));
                    }
                }
            }
            Err(e) => {
                let error_message = format!("Failed to analyze project for dependencies: {}", e);
                eprintln!("❌ handle_dependencies error: {}", &error_message);
                Err(CallToolError::new(AnalyzeToolError(error_message)))
            }
        }
    }
}

// --- Create a Tool Box ---
// This generates an enum `ServerTools` that contains all our defined tools.
tool_box!(
    ServerTools,
    [
        AboutInfoTool,
        AnalysisScanTool,
        SecurityScanTool,
        DependencyScanTool
    ]
);

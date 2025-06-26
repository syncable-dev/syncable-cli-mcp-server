// src/main_rest.rs

use axum::{
    extract::Json,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use futures::future::{BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber;

mod tools;
use tools::ServerTools;
use rust_mcp_sdk::schema::CallToolRequestParams;

/// JSON-RPC 2.0 request envelope
#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Option<Value>,
}

/// JSON-RPC 2.0 error object
#[derive(Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// JSON-RPC 2.0 response envelope
#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error:  Option<JsonRpcError>,
}

/// GET /mcp → 405 Method Not Allowed (we don’t do SSE here)
async fn mcp_get() -> (StatusCode, &'static str) {
    (StatusCode::METHOD_NOT_ALLOWED, "")
}

/// POST /mcp → JSON-RPC handler, boxed to ensure `Send`
fn mcp_post(Json(req): Json<JsonRpcRequest>) -> BoxFuture<'static, Json<JsonRpcResponse>> {
    async move {
        let id = Some(req.id.clone());

        // Must be JSON-RPC 2.0
        if req.jsonrpc != "2.0" {
            return Json(JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError { code: -32600, message: "Invalid Request".into() }),
            });
        }

        // Dispatch
        let response = match req.method.as_str() {
            // --- initialize handshake ---
            "initialize" => {
                #[derive(Deserialize)]
                struct InitParams {
                    protocolVersion: String,
                    #[serde(default)] capabilities: Value,
                }
                match req.params
                    .and_then(|p| serde_json::from_value::<InitParams>(p).ok())
                {
                    Some(p) => {
                        let result = json!({
                            "protocolVersion": p.protocolVersion,
                            "capabilities": { "tools": {} },
                            "serverInfo": {
                                "name": "rust-mcp-server-syncable",
                                "version": env!("CARGO_PKG_VERSION")
                            }
                        });
                        JsonRpcResponse { jsonrpc: "2.0", id, result: Some(result), error: None }
                    }
                    None => JsonRpcResponse {
                        jsonrpc: "2.0",
                        id,
                        result: None,
                        error: Some(JsonRpcError { code: -32602, message: "Invalid params for initialize".into() }),
                    },
                }
            }

            // --- list tools ---
            "tools/list" => {
                let list = ServerTools::tools()
                    .into_iter()
                    .map(|t| serde_json::to_value(t).unwrap())
                    .collect::<Vec<_>>();
                let result = json!({ "tools": list });
                JsonRpcResponse { jsonrpc: "2.0", id, result: Some(result), error: None }
            }

            // --- call a tool ---
            "tools/call" => {
                // 1) Extract the raw params Value
                let params_val = match req.params {
                    Some(v) => v,
                    None => {
                        return Json(JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: None,
                            error: Some(JsonRpcError { code: -32602, message: "Missing params for tools/call".into() }),
                        })
                    }
                };

                // 2) Parse into our typed params
                let params_typed: CallToolRequestParams = match serde_json::from_value(params_val) {
                    Ok(p) => p,
                    Err(_) => {
                        return Json(JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: None,
                            error: Some(JsonRpcError { code: -32602, message: "Invalid params for tools/call".into() }),
                        })
                    }
                };

                // 3) Try to build the tool enum, mapping any CallToolError → String immediately
                let tool_res: Result<ServerTools, String> = match ServerTools::try_from(params_typed) {
                    Ok(tool) => Ok(tool),
                    Err(e)   => Err(e.to_string()),
                };

                // 4) Compute the JSON result
                let result_json = match tool_res {
                    Err(err_msg) => json!({ "error": err_msg }),

                    Ok(tool_call) => match tool_call {
                        // Sync tools:
                        ServerTools::AboutInfoTool(t) => {
                            match t.call_tool() {
                                Ok(res) => serde_json::to_value(res)
                                    .unwrap_or_else(|e| json!({"error": format!("Serialization error: {}", e)})),
                                Err(e)  => json!({ "error": e.to_string() }),
                            }
                        }
                        ServerTools::AnalysisScanTool(t) => {
                            match t.call_tool() {
                                Ok(res) => serde_json::to_value(res)
                                    .unwrap_or_else(|e| json!({"error": format!("Serialization error: {}", e)})),
                                Err(e)  => json!({ "error": e.to_string() }),
                            }
                        }
                        ServerTools::SecurityScanTool(t) => {
                            match t.call_tool() {
                                Ok(res) => serde_json::to_value(res)
                                    .unwrap_or_else(|e| json!({"error": format!("Serialization error: {}", e)})),
                                Err(e)  => json!({ "error": e.to_string() }),
                            }
                        }

                        // Async tool: only this arm `.await`s, but holds no non-Send across it
                        ServerTools::DependencyScanTool(t) => {
                            match t.call_tool().await {
                                Ok(res) => serde_json::to_value(res)
                                    .unwrap_or_else(|e| json!({"error": format!("Serialization error: {}", e)})),
                                Err(e)  => json!({ "error": e.to_string() }),
                            }
                        }
                    },
                };

                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(result_json),
                    error: None,
                }
            }

            // --- unknown method ---
            _ => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError { code: -32601, message: "Method not found".into() }),
            },
        };

        Json(response)
    }
    .boxed()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/mcp", get(mcp_get).post(mcp_post));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    println!("MCP server listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

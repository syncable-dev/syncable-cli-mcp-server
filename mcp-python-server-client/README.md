# MCP Python Client & Demos

This package provides Python clients and demos for interacting with the [Syncable MCP Rust Server](../rust-mcp-server-syncable-cli/README.md). It supports both stdio and SSE transports, enabling AI agents and tools to perform code analysis, security scanning, and dependency checks.

---

## 📦 Folder Structure

```
mcp-python-server-client/
├── src/
│   ├── langgraph_sse_demo.py
│   ├── langgraph_stdio_demo.py
│   ├── mcp_py_client_rust_server_sse.py
│   ├── mcp_py_client_rust_server_stdio.py
│   ├── py_client_sse.py
│   ├── py_client_stdio.py
│   └── utils.py
├── .env
├── .python-version
├── LICENSE
├── pyproject.toml
├── README.md
└── uv.lock
```

---

## 🚀 Quick Start

### 1. Install Rust MCP Server

Follow instructions in [rust-mcp-server-syncable-cli/README.md](../rust-mcp-server-syncable-cli/README.md):

```bash
cd rust-mcp-server-syncable-cli
cargo build --release
# For stdio mode:
./target/release/mcp-stdio
# For SSE mode:
./target/release/mcp-sse
```

### 2. Set Up Python Environment

Install [uv](https://github.com/astral-sh/uv) (recommended for fast Python dependency management):

```bash
brew install uv
```

Sync dependencies:

```bash
uv sync
```

### 3. Install Required Python Packages

```bash
uv add langgraph openai python-dotenv langchain_mcp_adapters
```

---

## 🧑‍💻 Usage

### Run Python Demos

**Stdio Client Example:**

```bash
uv run python -m src.mcp_py_client_rust_server_stdio
```

**SSE Client Example:**

```bash
uv run python -m src.mcp_py_client_rust_server_sse
```

**LangGraph Integration (Stdio):**

```bash
uv run python -m src.langgraph_stdio_demo
```

**LangGraph Integration (SSE):**

```bash
uv run python -m src.langgraph_sse_demo
```

---

## 🛠️ Features

- **Multi-Transport:** Connect via stdio or SSE to the Rust MCP server.
- **Tooling:** List and invoke tools such as `about_info`, `analysis_scan`, `security_scan`, and `dependency_scan`.
- **LangGraph Integration:** Example agents using [LangGraph](https://github.com/langchain-ai/langgraph).
- **Extensible:** Easily add new tools or adapt to other agent frameworks.

---

## 🧪 Testing

Run Python tests:

```bash
pytest
```

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).

---

## 🙏 Acknowledgments

- Powered by [Syncable MCP Rust Server](../rust-mcp-server-syncable-cli/README.md)
- Built with [LangGraph](https://github.com/langchain-ai/langgraph), [OpenAI](https://openai.com/), and
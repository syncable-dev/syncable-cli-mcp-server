# 🚀 Syncable MCP Server & Python Client

> High-performance Model Context Protocol (MCP) server in Rust with a Python client for seamless integration and rapid prototyping.

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚡ Quick Start

### 1. Build & Run the Rust MCP Server

```bash
cd mcp-rust-server
cargo build --release
./target/release/mcp-stdio  # or ./target/release/mcp-sse for SSE mode
```

### 2. Use the Python Client

```bash
cd mcp-python-server-client
uv sync

# Example usage
uv run python -m src.mcp_py_client_rust_server_stdio
```

---

## 🎯 What This Project Does

- **MCP Rust Server**: Fast, scalable server implementing the Model Context Protocol (MCP) for code analysis, LLM integration, and more.
- **Python Client**: Easy-to-use Python interface for communicating with the Rust server via stdio or SSE.
- **Multi-language**: Designed for integration with various tools and languages.

---

## 📋 Key Features

- 🚀 **Blazing Fast**: Rust-powered backend for maximum performance
- 🔌 **Flexible Protocols**: Supports both stdio and SSE communication
- 🐍 **Python Client**: Simple API for rapid prototyping and integration
- 🛡️ **Secure**: Built with modern Rust safety guarantees
- 🧩 **Extensible**: Easy to add new handlers and endpoints

---

## 🛠️ Installation

### Rust Server

```bash
cd mcp-rust-server
cargo build --release
```

### Python Client

```bash
cd mcp-python-server-client
pip install -e .  # or pip install .
```

---

## 📖 Usage Guide

### Start the Rust Server

```bash
cd mcp-rust-server
./target/release/mcp-stdio
```

Or for SSE mode:

```bash
./target/release/mcp-sse
```

### Use the Python Client

```python
from mcp_py_client_rust_server_stdio import main as run_client
run_client()
```

Or run the provided scripts directly:

```bash
uv run python -m src.mcp_py_client_rust_server_stdio
```

---

## 🧪 Development & Testing

### Rust

```bash
cd mcp-rust-server
cargo test
cargo clippy
cargo fmt
```

### Python

```bash
cd mcp-python-server-client
pytest
```

---

## 🤝 Contributing

We welcome contributions! Please open issues or pull requests. For major changes, open an issue first to discuss what you’d like to change.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with Rust 🦀 and Python 🐍, powered by the open-source community.

---

**Need help?** Check the `docs/` folder or open an issue.

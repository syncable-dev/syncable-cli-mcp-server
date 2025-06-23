# 🦀 MCP Rust Server

> High-performance Model Context Protocol (MCP) server for code analysis, security scanning, and project insights.

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/mcp-rust-server?style=for-the-badge)](https://crates.io/crates/mcp-rust-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)

---

## ✨ Features

- **Fast & Scalable**: Built with async Rust for maximum performance
- **Flexible Protocols**: Supports both stdio and SSE communication
- **Security & Vulnerability Scanning**: Analyze codebases for risks and vulnerabilities
- **Extensible**: Add new handlers and endpoints easily
- **Production Ready**: Optimized release profile and logging

---

## 🚀 Quick Start

### Build

```bash
cargo build --release
```

### Run (Stdio Mode)

```bash
cargo run --release --bin mcp-stdio
```

### Run (SSE Mode)

```bash
cargo run --release --bin mcp-sse
```

---

## 📦 Installation (from crates.io)

```bash
cargo install mcp-rust-server
```

---

## 🛠️ Usage

- Use as a standalone server for MCP protocol
- Integrate with Syncable CLI or other tools
- Communicate via stdio or SSE endpoints

---

## 🧪 Testing

```bash
cargo test
```

---

## 📄 License

MIT License - see [LICENSE](../LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Please open issues or pull requests for improvements.

---

## 📚 Documentation

- See the main project [README](../README.md) for integration and usage examples.
- API docs: Run `cargo doc --open`

---

## Ref
- [Rust-mcp-sdk](https://lib.rs/crates/rust-mcp-sdk)
- [Release tool](https://github.com/release-plz/release-plz)

**Built with Rust 🦀 and the open-source community.**

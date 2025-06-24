# mcp-rust-server

[![Crates.io](https://img.shields.io/crates/v/mcp-rust-server.svg?style=for-the-badge)](https://crates.io/crates/rust-mcp-server-syncable-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](LICENSE)

High-performance **Model Context Protocol** (MCP) server for code analysis, security scanning, and project insights—written in Rust 🦀.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)

  * [CLI Binaries](#cli-binaries)
  * [Library](#library)
* [Usage](#usage)
* [Documentation](#documentation)
* [Contributing](#contributing)
* [License](#license)
* [Acknowledgments](#acknowledgments)

---

## Features

* **Fast & Scalable**: Built with async Rust on the Tokio runtime
* **Multi-Protocol**: Supports both stdio and SSE (Server-Sent Events) transports
* **Security Scanning**: Static analysis and vulnerability detection
* **Extensible**: Easily add new MCP handlers and custom tools
* **Production-Ready**: Optimized release profile, structured logging, and CI integration

---

## Installation

mcp-rust-server is published on [crates.io]. You need a recent Rust toolchain (1.70+ recommended).

### CLI Binaries

```bash
cargo install rust-mcp-server-syncable-cli
```

This installs two binaries into your Cargo `bin` directory (usually `~/.cargo/bin`):

* `mcp-stdio` — stdin/stdout-based MCP server
* `mcp-sse`   — HTTP/SSE-based MCP server

### Library

Add to your project’s `Cargo.toml`:

```toml
[dependencies]
rust-mcp-server-syncable-cli = "0.1.0"
```

---

## Usage

### CLI Binaries

```bash
# Run the stdio-based server
mcp-stdio

# Run the SSE-based server
mcp-sse
```

By default, both servers will:

1. Read framed MCP requests (JSON-RPC) from the chosen transport
2. Dispatch to your registered handlers
3. Write framed MCP responses

### Library

```rust
use rust_mcp_server_syncable_cli::{start_stdio, start_sse};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Run as a stdio server
    start_stdio().await?;

    // Or run as an HTTP/SSE server
    // start_sse().await?;

    Ok(())
}
```

* `start_stdio()` initializes logging, registers tools, and listens on stdin/stdout.
* `start_sse()` spins up an HTTP server at `http://0.0.0.0:8000/mcp` and streams MCP responses.

---

## Documentation

Full API documentation is generated on [docs.rs]:

```bash
cargo doc --open
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Commit your changes (`git commit -m "Add feature"`)
4. Push to your fork (`git push origin feat/your-feature`)
5. Open a pull request

Run tests and lint before submitting:

```bash
cargo test
cargo fmt -- --check
cargo clippy -- -D warnings
```

---

## License

Licensed under the [MIT License]. See \[LICENSE] for details.

---

## Acknowledgments

* Built on top of the [rust-mcp-sdk]
* Inspired by the [Syncable CLI MCP Server]
* Thanks to the Rust community and all contributors

[crates.io]: https://crates.io/crates/mcp-rust-server
[docs.rs]: https://docs.rs/mcp-rust-server
[examples/]: https://github.com/syncable-dev/syncable-cli-mcp-server/tree/main/examples
[MIT License]: LICENSE
[rust-mcp-sdk]: https://crates.io/crates/rust-mcp-sdk
[Syncable CLI MCP Server]: https://github.com/syncable-dev/syncable-cli-mcp-server

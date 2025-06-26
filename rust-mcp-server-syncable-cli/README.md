# mcp-rust-server

High-performance **Model Context Protocol** (MCP) server for code analysis, security scanning, and project insights—written in Rust 🦀.

---

## Related Project

This MCP server exposes the capabilities of the [`syncable-cli`](https://crates.io/crates/syncable-cli) tool to AI agents. While `syncable-cli` is a standalone CLI tool for interacting with Syncable workspaces, this server acts as a bridge, allowing AI agents and other clients to access those CLI features programmatically via the Model Context Protocol (MCP). Both projects are closely related and complement each other.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
  * [CLI Binaries](#cli-binaries)
  * [Add to PATH](#add-to-path)
  * [Python Client Example](#python-client-example)
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

`rust-mcp-server-syncable-cli` is published on [crates.io]. You need a recent Rust toolchain (1.70+ recommended). It works as an MCP server for AI agents where you can use the langgraph framework or similar to connect to this MCP server for code scanning.

### CLI Binaries

Install the server binaries from [crates.io](https://crates.io/crates/rust-mcp-server-syncable-cli):

```bash
cargo install rust-mcp-server-syncable-cli
```

This installs two binaries into your Cargo `bin` directory (usually `~/.cargo/bin`):

* `mcp-stdio` — stdin/stdout-based MCP server
* `mcp-sse`   — HTTP/SSE-based MCP server

---

### Add to PATH

If you see a warning like:

> be sure to add `/Users/yourname/.cargo/bin` to your PATH to be able to run the installed binaries

Add the following to your shell profile:

For **zsh** (default on recent macOS):
```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

For **bash**:
```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bash_profile
source ~/.bash_profile
```

Verify installation:
```bash
which mcp-stdio
which mcp-sse
```

---

### Python Client Example

You can connect to the MCP server from Python using the [mcp](https://pypi.org/project/mcp/) client library or similar.  
Below is an example using `mcp.client.stdio` to launch and communicate with the Rust MCP server via stdio:

```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def main():
    async with stdio_client(
        StdioServerParameters(command="mcp-stdio")
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Tools:", tools)

            # Call the 'about_info' tool
            about_info_result = await session.call_tool("about_info", {})
            print("About info result:", about_info_result)

            # Call the 'analysis_scan' tool
            code_analyze_result = await session.call_tool("analysis_scan", {"path": ".", "display": "matrix"})
            print("Code analysis result:", code_analyze_result)

            # Call the 'security_scan' tool
            security_scan_result = await session.call_tool("security_scan", {"path": "."})
            print("Security scan result:", security_scan_result)

            # Call the 'dependency_scan' tool
            dependency_scan_result = await session.call_tool("dependency_scan", {"path": "."})
            print("Dependency scan result:", dependency_scan_result)

asyncio.run(main())
```

**Requirements:**
- Install the Python MCP client:  
  ```bash
  pip install mcp
  ```
- Make sure `mcp-stdio` is in your `PATH` as described above.

#### Using HTTP/SSE Mode

If you prefer to use HTTP/SSE, start the server with:

```bash
mcp-sse
```

Then, in Python, you can send HTTP POST requests to `http://localhost:8000/mcp` using `requests` or `aiohttp`.

Example:
```python
import requests

payload = {
    "jsonrpc": "2.0",
    "method": "call_tool",
    "params": {
        "tool": "about_info",
        "args": {}
    },
    "id": 1
}

response = requests.post("http://localhost:8000/mcp", json=payload)
print(response.json())
```

---

### Library

Add to your project’s `Cargo.toml`:

```toml
[dependencies]
rust-mcp-server-syncable-cli = "0.1.4"
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

---

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

## Roadmap & Upcoming Features

### LangGraph Integration (Coming Soon 🚧)

We are planning to add **first-class support for the [LangGraph](https://github.com/langchain-ai/langgraph) framework**. This will include:

- **REST API Interface:**  
  Exposing a standard RESTful API (in addition to the current MCP stdio and SSE transports), making it easy to connect LangGraph and other agent frameworks without requiring a custom Python client.

- **Plug-and-Play LangGraph Support:**  
  Example workflows and documentation for integrating this MCP server as a tool node in LangGraph pipelines.

- **OpenAPI/Swagger Documentation:**  
  To make it easy to explore and test the REST endpoints.

**Stay tuned!** If you are interested in this feature or want to contribute, please open an issue or discussion on [GitHub](https://github.com/syncable-dev/syncable-cli-mcp-server).

---


## License

Licensed under the [MIT License]. See \[LICENSE] for details.

---

## Acknowledgments

* Built on top of the [rust-mcp-sdk]
* Inspired by the [Syncable CLI MCP Server]
* Thanks to the Rust community and all contributors

[crates.io]: https://crates.io/crates/rust-mcp-server-syncable-cli
[docs.rs]: https://docs.rs/rust-mcp-server-syncable-cli
[examples/]: https://github.com/syncable-dev/syncable-cli-mcp-server/tree/main/examples
[MIT License]: LICENSE
[rust-mcp-sdk]: https://crates.io/crates/rust-mcp-sdk
[Syncable CLI MCP Server]: https://github.com/syncable-dev/syncable-cli-mcp-server
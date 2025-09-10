## Local Development & Testing

### Prerequisites

- Rust 1.70+ (`rustup update`)
- Python 3.8+ (for client testing)
- [uv](https://github.com/astral-sh/uv) (`brew install uv` on macOS)

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/your-org/syncable-cli-mcp-server.git
cd syncable-cli-mcp-server
```

2. Build the project:
```bash
# Debug build
cargo build

# Release build
cargo build --release
```

The binaries will be available in:
- Debug: `./target/debug/mcp-stdio` and `./target/debug/mcp-sse`  
- Release: `./target/release/mcp-stdio` and `./target/release/mcp-sse`

### Testing the MCP Server

1. **Test Rust Components**:
```bash
# Run unit tests
cargo test

# Run with logging
RUST_LOG=debug cargo test
```

2. **Manual Testing with Python Client**:

First, start the MCP server in a terminal:
```bash
# For stdio mode
cargo run --bin mcp-stdio

# For SSE mode (in another terminal)
cargo run --bin mcp-sse
```

Then in another terminal, set up the Python environment:

```bash
# Setup Python environment
cd mcp-python-server-client

# Create and activate virtual environment using uv
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt
# Or use sync if you have a requirements.lock
uv sync

# Test stdio mode
uv run python -m src.mcp_py_client_rust_server_stdio

# Test SSE mode
uv run python src.mcp_py_client_rust_server_sse
```

3. **Verify Available Tools**:

The server should display available tools on startup. You should see:
- about_info
- analysis_scan
- security_scan
- dependency_scan

4. **Test Each Tool**:

```bash
# Using stdio mode for example
cargo run --bin mcp-stdio
```
In another terminal:
```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def test_tools():
    async with stdio_client(
        StdioServerParameters(command="../target/debug/mcp-stdio")
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Test about_info
            result = await session.call_tool("about_info", {})
            print("About Info:", result)
            
            # Test analysis_scan
            result = await session.call_tool("analysis_scan", 
                {"path": ".", "display": "matrix"})
            print("Analysis Scan:", result)
            
            # Test security_scan
            result = await session.call_tool("security_scan", {"path": "."})
            print("Security Scan:", result)
            
            # Test dependency_scan
            result = await session.call_tool("dependency_scan", {"path": "."})
            print("Dependency Scan:", result)

asyncio.run(test_tools())
```

5. **Integration Testing with LangGraph**:

```bash
# Install LangGraph dependencies
uv add langgraph openai python-dotenv langchain_mcp_adapters

# Test stdio integration
uv run python -m src.langgraph_stdio_demo

# Test SSE integration
uv run python -m src.langgraph_sse_demo
```

### Common Issues & Debugging

1. **Port Already in Use** (SSE mode):
```bash
lsof -i :8000  # Check if port 8000 is in use
kill -9 <PID>  # Kill the process if needed
```

2. **Binary Not Found** (stdio mode):
- Ensure the binary path in Python client matches your build location
- Check `cargo build` succeeded
- Verify binary permissions (`chmod +x` if needed)

3. **Enable Debug Logging**:
```bash
# For Rust server
RUST_LOG=debug cargo run --bin mcp-stdio

# For Python client
uv python -c "import logging; logging.basicConfig(level=logging.DEBUG)"
```

### Automated Release Process with release-plz

We use [release-plz](https://github.com/MarcoIeni/release-plz) to automate versioning and publishing. The workflow is configured in `.github/workflows/release-plz.yml`.

1. **Setup**:
```bash
# Install release-plz
cargo install release-plz

# Configure GitHub token
export GITHUB_TOKEN=your_github_token
export CARGO_REGISTRY_TOKEN=your_crates_io_token
```

2. **Check Release Status**:
```bash
# Preview what would be released
release-plz check
```

3. **Release Process**:
- Push your changes to the `main` branch
- The GitHub Action will automatically:
  - Update versions in Cargo.toml
  - Generate changelog entries
  - Create a release PR or publish directly
  - Push to crates.io when ready

4. **Manual Release** (if needed):
```bash
# Create changelog and bump version
release-plz release

# Update changelog only
release-plz update-changelog
```


### Manual Pre-release Checklist

Before publishing to crates.io:

1. All tests pass: `cargo test`
2. Code formatted: `cargo fmt --all -- --check`
3. No clippy warnings: `cargo clippy -- -D warnings`
4. Documentation up-to-date: `cargo doc --no-deps`
5. Version bumped in:
   - Cargo.toml
   - CHANGELOG.md
6. Python client examples work
7. Both transport modes (stdio/SSE) tested

### Publishing Process

Only after local testing succeeds:

```bash
# Login to crates.io
cargo login

# Dry run
cargo publish --dry-run

# Actual publish
cargo publish
```
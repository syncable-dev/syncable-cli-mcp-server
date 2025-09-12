# syncable-cli-mcp-server

# syncable-cli-mcp-server

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
  * [LangGraph Agent Integration](#langgraph-agent-integration)
  * [Library](#library)
* [Configuration](#configuration)
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

`rust-mcp-server-syncable-cli` is published on [crates.io](https://crates.io/crates/rust-mcp-server-syncable-cli). You need a recent Rust toolchain (1.70+ recommended). It works as an MCP server for AI agents where you can use the langgraph framework or similar to connect to this MCP server for code scanning.

### CLI Binaries

Install the server binaries from [crates.io](https://crates.io/crates/rust-mcp-server-syncable-cli):

```bash
cargo install rust-mcp-server-syncable-cli
```

This installs two binaries into your Cargo `bin` directory (usually `~/.cargo/bin`):

- `mcp-stdio` — stdin/stdout-based MCP server
- `mcp-sse`   — HTTP/SSE-based MCP server

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
            tools = await session.list_tools()
            print("Tools:", tools)
            about_info_result = await session.call_tool("about_info", {{}})
            print("About info result:", about_info_result)
            code_analyze_result = await session.call_tool("analysis_scan", {{"path": ".", "display": "matrix"}})
            print("Code analysis result:", code_analyze_result)
            security_scan_result = await session.call_tool("security_scan", {{"path": "."}})
            print("Security scan result:", security_scan_result)
            dependency_scan_result = await session.call_tool("dependency_scan", {{"path": "."}})
            print("Dependency scan result:", dependency_scan_result)

asyncio.run(main())
```

#### Using HTTP/SSE Mode

If you prefer to use HTTP/SSE, start the server with:

```bash
mcp-sse
```

```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from utils import render_utility_result  # Adjust import if needed

async def main():
    server_url = "http://127.0.0.1:8008/sse"
    async with sse_client(server_url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Tools:")
            render_utility_result(tools)

            # Call the 'about_info' tool
            about_info_result = await session.call_tool("about_info", {{}})
            print("About info result:")
            render_utility_result(about_info_result)

            # Call the 'analysis_scan' tool
            code_analyze_result = await session.call_tool("analysis_scan", {{"path": "../", "display": "matrix"}})
            print("Code analysis result:")
            render_utility_result(code_analyze_result)

            # Call the 'security_scan' tool
            security_scan_result = await session.call_tool("security_scan", {{"path": "../"}})
            print("Security scan result:")
            render_utility_result(security_scan_result)

            # Call the 'dependency_scan' tool
            dependency_scan_result = await session.call_tool("dependency_scan", {{"path": "../"}})
            print("Dependency scan result:")
            render_utility_result(dependency_scan_result)

if __name__ == "__main__":
    asyncio.run(main())
```

---


### LangGraph Agent Integration
You can use the LangGraph framework to connect to this MCP server in both stdio and SSE modes. Below are example Python scripts for each mode.

Using Stdio Mode
This example launches the mcp-stdio binary and connects via stdio:

```python
import asyncio
import os
from dotenv import load_dotenv

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    client = MultiServerMCPClient({
        "syncable_cli": {
            # Adjust this path if needed—just needs to point
            # at your compiled mcp-stdio binary.
            "command": "../rust-mcp-server-syncable-cli/target/release/mcp-stdio",
            "args": [],              # no extra args
            "transport": "stdio",    # stdio transport
        }
    })

    tools = await client.get_tools()
    print(f"Fetched {len(tools)} tools:")
    for t in tools:
        print(f" • {t.name}")

    agent = create_react_agent("openai:gpt-4o", tools)

    tests = [
        ("about_info",    "Call the 'about_info' tool."),
        ("analysis_scan", "Call 'analysis_scan' on path '../' with display 'matrix'."),
        ("security_scan", "Call 'security_scan' on path '../'."),
        ("dependency_scan","Call 'dependency_scan' on path '../'."),
    ]

    for name, prompt in tests:
        print(f"\n--- {name} → {prompt}")
        resp = await agent.ainvoke({
            "messages": [{"role": "user", "content": prompt}]
        })
        print(resp)

if __name__ == "__main__":
    asyncio.run(main())
```

Using HTTP/SSE Mode
This example connects to the MCP server via HTTP/SSE:

```python
import asyncio
import os
from dotenv import load_dotenv

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    # ← Use /sse here, since `mcp-sse` prints "Server is available at .../sse"
    client = MultiServerMCPClient({
        "demo": {
            "url": "http://127.0.0.1:8008/sse",
            "transport": "sse",
        }
    })

    tools = await client.get_tools()
    print(f"Fetched {len(tools)} tools from MCP server:")
    for t in tools:
        print(f" • {t.name}")

    agent = create_react_agent("openai:gpt-4o", tools)

    prompts = [
        ("about_info",     "Call the 'about_info' tool."),
        ("analysis_scan",  "Call the 'analysis_scan' tool on path '../' with display 'matrix'."),
        ("security_scan",  "Call the 'security_scan' tool on path '../'."),
        ("dependency_scan","Call the 'dependency_scan' tool on path '../'."),
    ]

    for name, prompt in prompts:
        print(f"\n--- Invoking {name} ---")
        resp = await agent.ainvoke({
            "messages": [{"role": "user", "content": prompt}]
        })
        print(resp)

if __name__ == "__main__":
    asyncio.run(main())
```

---


## Configuration

The SSE server port can be configured using the `MCP_PORT` environment variable.

-   **`MCP_PORT`**: Sets the port for the SSE server.
    -   **Default**: `8008`

Example of running the server on a custom port:

```bash
MCP_PORT=9000 mcp-sse
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
cargo doc --open
```

---


## License

Licensed under the [MIT License](LICENSE). See [LICENSE](LICENSE) for details.

---


## Acknowledgments

- Built on [rust-mcp-sdk](https://crates.io/crates/rust-mcp-sdk)
- Inspired by [Syncable CLI MCP Server](https://github.com/syncable-dev/syncable-cli-mcp-server)
- Thanks to the Rust and Python communities!

[crates.io]: https://crates.io/crates/rust-mcp-server-syncable-cli
[docs.rs]: https://docs.rs/rust-mcp-server-

## Konwn Issues
- langgraph using sse version is still under development and is not functioning well. (Fixed: json output is set to be true)
- when use json output, stdio protocal has limitations on the size of json file 8k, which causes programe to hang if the analyze scan result is too big. If this protocal is rally needed, try to disable the json output in analysis_scan


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
  * [LangGraph Agent Integration](#langgraph-agent-integration)
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

- `mcp-stdio` — stdin/stdout-based MCP server
- `mcp-sse`   — HTTP/SSE-based MCP server

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
            tools = await session.list_tools()
            print("Tools:", tools)
            about_info_result = await session.call_tool("about_info", {})
            print("About info result:", about_info_result)
            code_analyze_result = await session.call_tool("analysis_scan", {"path": ".", "display": "matrix"})
            print("Code analysis result:", code_analyze_result)
            security_scan_result = await session.call_tool("security_scan", {"path": "."})
            print("Security scan result:", security_scan_result)
            dependency_scan_result = await session.call_tool("dependency_scan", {"path": "."})
            print("Dependency scan result:", dependency_scan_result)

asyncio.run(main())
```

#### Using HTTP/SSE Mode

If you prefer to use HTTP/SSE, start the server with:

```bash
mcp-sse
```

```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from utils import render_utility_result  # Adjust import if needed

async def main():
    server_url = "http://127.0.0.1:8000/sse"
    async with sse_client(server_url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Tools:")
            render_utility_result(tools)

            # Call the 'about_info' tool
            about_info_result = await session.call_tool("about_info", {})
            print("About info result:")
            render_utility_result(about_info_result)

            # Call the 'analysis_scan' tool
            code_analyze_result = await session.call_tool("analysis_scan", {"path": "../", "display": "matrix"})
            print("Code analysis result:")
            render_utility_result(code_analyze_result)

            # Call the 'security_scan' tool
            security_scan_result = await session.call_tool("security_scan", {"path": "../"})
            print("Security scan result:")
            render_utility_result(security_scan_result)

            # Call the 'dependency_scan' tool
            dependency_scan_result = await session.call_tool("dependency_scan", {"path": "../"})
            print("Dependency scan result:")
            render_utility_result(dependency_scan_result)

if __name__ == "__main__":
    asyncio.run(main())
```

---

### LangGraph Agent Integration
You can use the LangGraph framework to connect to this MCP server in both stdio and SSE modes. Below are example Python scripts for each mode.

Using Stdio Mode
This example launches the mcp-stdio binary and connects via stdio:

```python
import asyncio
import os
from dotenv import load_dotenv

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    client = MultiServerMCPClient({
        "syncable_cli": {
            # Adjust this path if needed—just needs to point
            # at your compiled mcp-stdio binary.
            "command": "../rust-mcp-server-syncable-cli/target/release/mcp-stdio",
            "args": [],              # no extra args
            "transport": "stdio",    # stdio transport
        }
    })

    tools = await client.get_tools()
    print(f"Fetched {len(tools)} tools:")
    for t in tools:
        print(f" • {t.name}")

    agent = create_react_agent("openai:gpt-4o", tools)

    tests = [
        ("about_info",    "Call the 'about_info' tool."),
        ("analysis_scan", "Call 'analysis_scan' on path '../' with display 'matrix'."),
        ("security_scan", "Call 'security_scan' on path '../'."),
        ("dependency_scan","Call 'dependency_scan' on path '../'."),
    ]

    for name, prompt in tests:
        print(f"\n--- {name} → {prompt}")
        resp = await agent.ainvoke({
            "messages": [{"role": "user", "content": prompt}]
        })
        print(resp)

if __name__ == "__main__":
    asyncio.run(main())
```

Using HTTP/SSE Mode
This example connects to the MCP server via HTTP/SSE:

```python
import asyncio
import os
from dotenv import load_dotenv

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    # ← Use /sse here, since `mcp-sse` prints "Server is available at .../sse"
    client = MultiServerMCPClient({
        "demo": {
            "url": "http://127.0.0.1:8000/sse",
            "transport": "sse",
        }
    })

    tools = await client.get_tools()
    print(f"Fetched {len(tools)} tools from MCP server:")
    for t in tools:
        print(f" • {t.name}")

    agent = create_react_agent("openai:gpt-4o", tools)

    prompts = [
        ("about_info",     "Call the 'about_info' tool."),
        ("analysis_scan",  "Call the 'analysis_scan' tool on path '../' with display 'matrix'."),
        ("security_scan",  "Call the 'security_scan' tool on path '../'."),
        ("dependency_scan","Call the 'dependency_scan' tool on path '../'."),
    ]

    for name, prompt in prompts:
        print(f"\n--- Invoking {name} ---")
        resp = await agent.ainvoke({
            "messages": [{"role": "user", "content": prompt}]
        })
        print(resp)

if __name__ == "__main__":
    asyncio.run(main())
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
cargo doc --open
```

---

## License

Licensed under the [MIT License](LICENSE). See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Built on [rust-mcp-sdk](https://crates.io/crates/rust-mcp-sdk)
- Inspired by [Syncable CLI MCP Server](https://github.com/syncable-dev/syncable-cli-mcp-server)
- Thanks to the Rust and Python communities!

[crates.io]: https://crates.io/crates/rust-mcp-server-syncable-cli
[docs.rs]: https://docs.rs/rust-mcp-server-

## Konwn Issues
- langgraph using sse version is still under development and is not functioning well. (Fixed: json output is set to be true)
- when use json output, stdio protocal has limitations on the size of json file 8k, which causes programe to hang if the analyze scan result is too big. If this protocal is rally needed, try to disable the json output in analysis_scan












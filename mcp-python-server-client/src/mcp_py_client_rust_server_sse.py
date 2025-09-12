import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from .utils import render_utility_result

# to start the server, run from the `rust-mcp-server-syncable-cli` directory:
# cargo run --release --bin mcp-sse

async def main():
    # The URL where the Rust SSE server is listening.
    server_url = "http://127.0.0.1:8008/sse"

    async with sse_client(server_url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Tools:")
            render_utility_result(tools)

            # Call the 'about info' tool
            about_info_result = await session.call_tool("about_info", {})
            print("About info result:")
            render_utility_result(about_info_result)

            code_analyze_result = await session.call_tool("analysis_scan", {"path": "../", "display": "matrix"})
            print("Code analysis result:")
            render_utility_result(code_analyze_result)

            # Call the 'security scan' tool
            security_scan_result = await session.call_tool("security_scan", {"path": "../"})
            print("Security scan result:")
            render_utility_result(security_scan_result)

            # Call the 'dependency scan' tool
            dependency_scan_result = await session.call_tool("dependency_scan", {"path": "../"})
            print("Dependency scan result:")
            render_utility_result(dependency_scan_result)


if __name__ == "__main__":
    asyncio.run(main())

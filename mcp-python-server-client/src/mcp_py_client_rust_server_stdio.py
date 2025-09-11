import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from .utils import render_utility_result

# to start the server, run:
# from cpr-rust-server folder cargo run --release 

async def main():
    async with stdio_client(
        StdioServerParameters(command="../rust-mcp-server-syncable-cli/target/release/mcp-stdio")
        #StdioServerParameters(command="mcp-stdio")
    ) as (read, write):
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

            code_analyze_result = await session.call_tool("analysis_scan", {"path": "../", "display": "summary"})
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


asyncio.run(main())
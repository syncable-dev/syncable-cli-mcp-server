import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pprint import pprint

# to start the server, run:
# from cpr-rust-server folder cargo run --release 

def render_utility_result(result):
    """
    Parses and prints the formatted result from a tool.
    It can handle both raw formatted strings (with ANSI codes) and
    JSON-encoded strings containing a formatted report.
    """
    if not result or not result.content or result.isError:
        print("Invalid or error result.")
        pprint(result)
        return

    try:
        # The result is a single TextContent object
        text_content = result.content[0].text
        
        try:
            # First, try to load as JSON. This handles tool outputs that
            # are JSON-encoded strings (e.g., a report string inside a JSON string).
            report_string = json.loads(text_content)
            print(report_string)
        except json.JSONDecodeError:
            # If JSON decoding fails, assume it's a raw, pre-formatted string
            # (like the output from the 'about_info' tool with ANSI codes).
            print(text_content)
            
    except (IndexError, AttributeError) as e:
        print(f"Error parsing result: {e}")
        print("Printing raw result instead:")
        pprint(result)


async def main():
    async with stdio_client(
        StdioServerParameters(command="../mcp-rust-server/target/release/mcp-stdio")
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Tools:")
            pprint(tools)

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


asyncio.run(main())
import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pprint import pprint

# to start the server, run:
# from cpr-rust-server folder cargo run --release 

def render_utility_result(result):
    """
    Parses and prints the formatted security scan result.
    The result from the tool is a JSON-encoded string containing the formatted report.
    This function decodes it and prints it to the console.
    """
    if not result or not result.content or result.isError:
        print("Invalid or error security scan result.")
        pprint(result)
        return

    try:
        # The result is a single TextContent object
        text_content = result.content[0].text
        
        # The text is a JSON-encoded string. Loading it unescapes the content.
        report_string = json.loads(text_content)
        
        # Print the human-readable report
        print(report_string)
    except (json.JSONDecodeError, IndexError, AttributeError) as e:
        print(f"Error parsing security scan result: {e}")
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
            code_analyze_result = await session.call_tool("analyzeProject", {"path": "../", "display": "detailed"})
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
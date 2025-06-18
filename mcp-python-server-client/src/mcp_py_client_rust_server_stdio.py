import asyncio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# to start the server, run:
# from cpr-rust-server folder cargo run --release 

async def main():
    async with stdio_client(
        StdioServerParameters(command="../mcp-rust-server/target/release/mcp-stdio")
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # List available tools
            tools = await session.list_tools()
            print("Tools:", tools)
            # Call the 'add' tool
            add_result = await session.call_tool("add", {"a": 2, "b": 3})
            print("Add result:", add_result)
            # Call the 'multiply' tool
            multiply_result = await session.call_tool("multiply", {"a": 4, "b": 5})
            print("Multiply result:", multiply_result)
            # Call the 'reverse' tool
            reverse_result = await session.call_tool("reverse", {"text": "hello"})
            print("Reverse result:", reverse_result)
            # Call the 'code analysis' tool
            code_analyze_result = await session.call_tool("analyzeProject", {"path": "../../", "display": "matrix"})
            print("Code analysis result:", code_analyze_result)
            """
            # TODO: these needs to valided with rust-mcp-server which may not be implemented yet
            # List resources
            resources = await session.list_resources()
            print("Resources:", resources)
            # Read a static resource
            about = await session.read_resource("info://about")
            print("About resource:", about)
            # Read a dynamic resource
            greeting = await session.read_resource("greeting://Alice")
            print("Greeting:", greeting)
            # List prompts
            prompts = await session.list_prompts()
            print("Prompts:", prompts)
            # Call the 'summarize' prompt
            summary = await session.get_prompt("summarize", {"text": "This is a long text that should be summarized."})
            print("Summary:", summary)
            """

asyncio.run(main())
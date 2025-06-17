import asyncio
from mcp.client.session import ClientSession
# Import the sse_client instead of stdio_client
from mcp.client.sse import sse_client

# Instructions:
# 1. Start the Rust SSE server in a separate terminal:
#    cargo run --release --bin mcp-rust-server (or whatever your SSE binary is named)
# 2. Run this Python script.

async def main():
    # The URL where the Rust SSE server is listening.
    # The sse_client requires the full endpoint, which is typically /mcp.
    server_url = "http://127.0.0.1:8001/sse"

    # Use the sse_client context manager with the server URL
    async with sse_client(server_url) as (read, write):
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
            
            # Calling the tools we created to mimic resources and prompts
            about_result = await session.call_tool("about_info", {})
            print("About Info result:", about_result)

            greeting_result = await session.call_tool("greeting", {"name": "Alice"})
            print("Greeting result:", greeting_result)

            summary_result = await session.call_tool("summarize", {"text": "This is a long text that should be summarized."})
            print("Summary result:", summary_result)


if __name__ == "__main__":
    asyncio.run(main())

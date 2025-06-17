import asyncio
import os
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

# remeber to start the sse server first
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    # Connect to HTTP-based MCP server using SSE
    client = MultiServerMCPClient({
        "demo": {
            "url": "http://127.0.0.1:8000/mcp",
            "transport": "streamable_http"
        }
    })

    # Get available tools from server
    tools = await client.get_tools()

    # Create an agent using GPT-4o and those tools
    agent = create_react_agent("openai:gpt-4o", tools)

    # Ask a question that might invoke one of the tools
    response = await agent.ainvoke({
        "messages": [{"role": "user", "content": "Can you add 3 and 5 for me?"}]
    })

    print(response)

asyncio.run(main())

import asyncio
import os
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

# Load .env file
load_dotenv()

# Set OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    # Start the MCP client with a math tool
    client = MultiServerMCPClient({
        "math": {
            "command": "python",
            "args": ["src/demo_server.py"],  # Your MCP server file
            "transport": "stdio"
        }
    })

    # Load tools provided by the MCP server
    tools = await client.get_tools()

    # Create the ReAct agent using GPT-4o and the tools
    agent = create_react_agent("openai:gpt-4o", tools)

    # Send a message to the agent
    response = await agent.ainvoke({
        "messages": [{"role": "user", "content": "What is 2 + 2?"}]
    })

    print(response)

# Run the async function
asyncio.run(main())

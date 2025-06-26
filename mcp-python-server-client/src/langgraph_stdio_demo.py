import asyncio
import os
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

# Load .env file
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    client = MultiServerMCPClient({
        "math": {
            "command": "python",
            "args": ["src/demo_server.py"],
            "transport": "stdio"
        }
    })

    tools = await client.get_tools()
    print(f"Fetched {len(tools)} tools from MCP server.")
    for tool in tools:
        print(f"- {tool.name}")

    agent = create_react_agent("openai:gpt-4o", tools)

    prompts = [
        ("about_info", "Call the 'about_info' tool."),
        ("analysis_scan", "Call the 'analysis_scan' tool on path '../' with display 'matrix'."),
        ("security_scan", "Call the 'security_scan' tool on path '../'."),
        ("dependency_scan", "Call the 'dependency_scan' tool on path '../'.")
    ]

    for tool_name, prompt in prompts:
        print(f"\nInvoking agent to call '{tool_name}'...")
        response = await agent.ainvoke({
            "messages": [
                {"role": "user", "content": prompt}
            ]
        })
        print(f"Result for '{tool_name}':")
        print(response)

asyncio.run(main())

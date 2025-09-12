# src/langgraph_sse_demo.py

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

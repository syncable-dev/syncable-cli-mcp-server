# src/langgraph_stdio_demo.py

import asyncio
import os
from dotenv import load_dotenv

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

async def main():
    client = MultiServerMCPClient({
        "syncable_cli": {
            # Adjust this path if needed—just needs to point
            # at your compiled mcp-stdio binary.
            "command": "../rust-mcp-server-syncable-cli/target/release/mcp-stdio",
            "args": [],              # no extra args
            "transport": "stdio",    # stdio transport
        }
    })

    tools = await client.get_tools()
    print(f"Fetched {len(tools)} tools:")
    for t in tools:
        print(f" • {t.name}")

    agent = create_react_agent("openai:gpt-4o", tools)

    tests = [
        ("about_info",    "Call the 'about_info' tool."),
        ("analysis_scan", "Call 'analysis_scan' on path '../' with display 'matrix'."),
        ("security_scan", "Call 'security_scan' on path '../'."),
        ("dependency_scan","Call 'dependency_scan' on path '../'."),
    ]

    for name, prompt in tests:
        print(f"\n--- {name} → {prompt}")
        resp = await agent.ainvoke({
            "messages": [{"role": "user", "content": prompt}]
        })
        print(resp)

if __name__ == "__main__":
    asyncio.run(main())

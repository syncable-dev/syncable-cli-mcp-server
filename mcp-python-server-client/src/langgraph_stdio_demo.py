# src/langgraph_stdio_demo.py

import asyncio
import os
from dotenv import load_dotenv
from collections import namedtuple

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
import openai

from .utils import render_utility_result

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")


async def main():
    client = MultiServerMCPClient({
        "syncable_cli": {
            # Adjust this path if needed—just needs to point
            # at your compiled mcp-stdio binary.
            #"command": "../rust-mcp-server-syncable-cli/target/release/mcp-stdio",
            "command": "mcp-stdio",
            "args": [],              # no extra args
            "transport": "stdio",    # stdio transport
        }
    })

    tools = await client.get_tools()
    print(f"Fetched {len(tools)} tools:")
    for t in tools:
        print(f" • {t.name}")

    agent = create_react_agent("openai:gpt-4.1", tools)

    tests = [
        ("about_info",    "Call the 'about_info' tool."),
        ("analysis_scan", "Call 'analysis_scan' on path '../' with display 'matrix'."),
        ("security_scan", "Call 'security_scan' on path '../'."),
        ("dependency_scan","Call 'dependency_scan' on path '../'."),
    ]

    TextContent = namedtuple('TextContent', ['text'])
    ToolResult = namedtuple('ToolResult', ['content', 'isError'])

    for name, prompt in tests:
        print(f"\n--- {name} → {prompt}")
        tool_outputs = []
        agent_final_response = None

        # Stream through the agent's steps
        async for chunk in agent.astream({"messages": [{"role": "user", "content": prompt}]}
            ):
            if "tools" in chunk:
                tool_outputs.extend(chunk["tools"]["messages"])
            if "agent" in chunk:
                # The agent's message is the latest one in the list
                message = chunk["agent"]["messages"][-1]
                # If it's a final response (no more tool calls), we save it.
                if not message.tool_calls:
                    agent_final_response = message

        # Render the collected outputs. Prioritize tool output.
        if tool_outputs:
            # To make the output identical, we remove the "Tool output:" header
            for msg in tool_outputs:
                mock_result = ToolResult(content=[TextContent(text=msg.content)], isError=False)
                render_utility_result(mock_result)
        elif agent_final_response:
            # Only if no tool was called, print the agent's response.
            print(agent_final_response.content)

if __name__ == "__main__":
    asyncio.run(main())
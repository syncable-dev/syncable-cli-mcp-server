"""An MCP client for the Agno SSE demo."""

import asyncio
import os
from dotenv import load_dotenv
import openai

from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.mcp import MCPTools

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")


async def main():
    """Connects to an MCP server and uses it to run an agent."""
    server_url = "http://127.0.0.1:8008/sse"
    async with MCPTools(url=server_url, transport="sse") as mcp_tools:
        agent = Agent(model=OpenAIChat(id="gpt-4o"), tools=[mcp_tools])

        prompts = [
            "Call the 'about_info' tool.",
            "Call 'analysis_scan' on path '../' with display 'matrix'.",
            "Call 'security_scan' on path '../'.",
            "Call 'dependency_scan' on path '../'.",
        ]

        for prompt in prompts:
            print(f"\n--- Prompt: {prompt} ---")
            await agent.aprint_response(prompt, stream=True)


if __name__ == "__main__":
    asyncio.run(main())

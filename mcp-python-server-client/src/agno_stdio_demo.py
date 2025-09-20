"""A demo of the Agno MCP tools with a stdio transport."""

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
    """Fetches tools from a subprocess and uses them to run an agent."""
    async with MCPTools(command="uv run mcp-stdio") as mcp_tools:
        agent = Agent(model=OpenAIChat(id="gpt-4.1"), tools=[mcp_tools])

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
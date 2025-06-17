import asyncio
import os
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

# Instructions:
# 1. Make sure your .env file has your OPENAI_API_KEY.
# 2. Start the Rust SSE server in a separate terminal:
#    RUST_LOG=info cargo run --release --bin mcp-sse
# 3. Run this Python script.

# Load environment variables from .env file
load_dotenv()

async def main():
    """
    Connects to the Rust MCP server, fetches its tools, and uses them
    in a LangGraph agent to answer a question.
    """
    print("Attempting to connect to the Rust MCP SSE server...")

    # Correctly configure the client to connect to your Rust SSE server.
    # The transport must be 'sse' and the URL should be the base address.
    # The client library will handle appending the correct /sse endpoint.
    client = MultiServerMCPClient({
        "rust_server": {
            "url": "http://127.0.0.1:8001/sse",
            "transport": "sse"
        }
    })

    print("Fetching tools from the server...")
    try:
        tools = await client.get_tools()
        if not tools:
            print("Error: No tools were found on the server.")
            print("Please ensure the Rust server's `handle_list_tools_request` is implemented correctly.")
            return
        print(f"Successfully fetched {len(tools)} tools:")
        for tool in tools:
            print(f"- {tool.name}")
    except Exception as e:
        print(f"\n--- Connection Error ---")
        print(f"Failed to fetch tools: {e}")
        print("Please ensure the Rust SSE server is running and accessible at http://127.0.0.1:8000")
        print("------------------------")
        return

    # Create an agent using GPT-4o and the fetched tools
    print("\nCreating LangGraph agent with GPT-4o...")
    # Using the explicit ChatOpenAI class is more robust.
    # It will automatically use the OPENAI_API_KEY from your environment.
    llm = ChatOpenAI(model="gpt-4o")
    agent_executor = create_react_agent(llm, tools)

    # Ask a question that will invoke one of the tools from our Rust server
    user_query = "Can you add 3 and 5 for me?"
    print(f"\nInvoking agent with query: '{user_query}'")

    # The input to the agent is a dictionary with a 'messages' key
    input_data = {"messages": [{"role": "user", "content": user_query}]}

    response = await agent_executor.ainvoke(input_data)

    print("\n--- Agent Final Response ---")
    # The final response is in the 'messages' list, with the last message being from the 'assistant'
    final_message = response['messages'][-1]
    print(final_message.content)
    print("--------------------------")


if __name__ == "__main__":
    try:
        # Check for API key before running
        if not os.getenv("OPENAI_API_KEY"):
            print("Error: OPENAI_API_KEY not found in environment variables.")
            print("Please create a .env file and add your OpenAI API key to it.")
        else:
            asyncio.run(main())
    except ImportError:
        print("\nError: Required packages are not installed.")
        print("Please run: pip install langchain_mcp_adapters langgraph langchain_openai python-dotenv")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

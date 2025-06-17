# server.py
from mcp.server.fastmcp import FastMCP

# Create an MCP server
mcp = FastMCP("Demo")


# Add tools
@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b


@mcp.tool()
def multiply(a: int, b: int) -> int:
    """Multiply two numbers"""
    return a * b


@mcp.tool()
def reverse(text: str) -> str:
    """Reverse a string"""
    return text[::-1]


# Add static resource
@mcp.resource("info://about")
def about() -> str:
    """About this server"""
    return "This is a demo MCP server with tools and resources."


# Add dynamic resource
@mcp.resource("greeting://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    return f"Hello, {name}!"


# Add prompt
@mcp.prompt("summarize")
def summarize(text: str) -> str:
    """Summarize the given text"""
    return f"Summary: {text[:20]}..." if len(text) > 20 else f"Summary: {text}"

if __name__ == "__main__":
    # Start the server
    mcp.run(transport="stdio")
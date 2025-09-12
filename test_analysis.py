#!/usr/bin/env python3

import asyncio
import json
import sys
import os
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def test_analysis():
    # Ensure we're in the right directory
    server_path = "./rust-mcp-server-syncable-cli/target/release/mcp-stdio"
    
    if not os.path.exists(server_path):
        print(f"Server binary not found at {server_path}")
        return
    
    print(f"Using server binary: {server_path}")
    
    try:
        async with stdio_client(
            StdioServerParameters(command=server_path)
        ) as (read, write):
            async with ClientSession(read, write) as session:
                print("Initializing session...")
                await session.initialize()
                print("Session initialized")

                print("Calling analysis_scan tool...")
                # Add a timeout to prevent hanging
                result = await asyncio.wait_for(
                    session.call_tool("analysis_scan", {"path": "./rust-mcp-server-syncable-cli", "display": "matrix"}),
                    timeout=30.0  # 30 second timeout
                )
                print("Analysis result received:")
                print(f"Result type: {type(result)}")
                print(f"Result attributes: {dir(result)}")
                if hasattr(result, 'content'):
                    print(f"Content length: {len(result.content)}")
                    for i, content in enumerate(result.content):
                        print(f"Content[{i}]: {type(content)}")
                        if hasattr(content, 'text'):
                            print(f"Text length: {len(content.text)}")
                            print(f"First 500 chars: {content.text[:500]}")
                print("Full result:")
                print(json.dumps(result, indent=2, default=str))
                
    except asyncio.TimeoutError:
        print("Timeout: The analysis tool took too long to respond")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_analysis())
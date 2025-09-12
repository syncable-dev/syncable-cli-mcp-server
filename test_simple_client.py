#!/usr/bin/env python3
"""Simple test client to isolate the hanging issue."""

import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def test_tools():
    async with stdio_client(
        StdioServerParameters(command="rust-mcp-server-syncable-cli/target/release/mcp-stdio")
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("Testing about_info...")
            try:
                about_result = await session.call_tool("about_info", {})
                print("✅ about_info succeeded")
                print(f"Response length: {len(str(about_result))}")
            except Exception as e:
                print(f"❌ about_info failed: {e}")
            
            print("\nTesting security_scan...")
            try:
                security_result = await session.call_tool("security_scan", {"path": "."})
                print("✅ security_scan succeeded")
                print(f"Response length: {len(str(security_result))}")
            except Exception as e:
                print(f"❌ security_scan failed: {e}")
            
            print("\nTesting analysis_scan...")
            try:
                analysis_result = await session.call_tool("analysis_scan", {"path": ".", "display": "summary"})
                print("✅ analysis_scan succeeded")
                print(f"Response length: {len(str(analysis_result))}")
            except Exception as e:
                print(f"❌ analysis_scan failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_tools())
# ai-agents-mcp
Demos on using MCP for AI agents

## uv related
install uv

brew install uv
brew instal rust

## install MCP servers
uv run mcp install src/demo_server.py


## run MCP server
uv run mcp dev src/demo_server.py

cd mcp-rust-server
cargo build --release

cargo run

cargo add rust-mcp-server

cargo test
#!/bin/bash
# Setup script for MCP Swiss Knife

set -e

echo "Setting up MCP Swiss Knife..."

# Install dependencies
echo "Installing dependencies..."
uv sync

# Download spaCy model (using direct URL method)
echo "Downloading spaCy language model..."
uv pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

echo "Setup complete! You can now run:"
echo "  uv run mcp-swiss-knife scan <MCP_SERVER_URL>"

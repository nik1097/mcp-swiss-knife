"""MCP client for connecting to MCP servers."""

import json
import logging
from typing import Any, Dict, Optional

import requests

from .config import HTTP_TIMEOUT, MAX_TOOLS_PER_SERVER

logger = logging.getLogger(__name__)


class MCPClient:
    """HTTP MCP client using JSON-RPC 2.0 over SSE."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        from . import __version__

        # Input validation
        if not base_url:
            raise ValueError("base_url cannot be empty")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout or HTTP_TIMEOUT
        self.request_id = 0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
        )

        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

        self.session.headers["User-Agent"] = f"mcp-swiss-knife/{__version__}"

    def _parse_sse_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse SSE response and extract JSON-RPC result."""
        for line in response.iter_lines(decode_unicode=True):
            if not line or line.startswith(":"):
                continue
            if line.startswith("data: "):
                try:
                    data = json.loads(line[6:])
                    if (
                        data.get("jsonrpc") == "2.0"
                        and data.get("id") == self.request_id
                    ):
                        if "error" in data:
                            error = data["error"]
                            error_msg = f"MCP error: {error.get('message', error)}"
                            logger.error(error_msg)
                            raise ValueError(error_msg)
                        return data.get("result", {})
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse SSE line: {e}")
                    continue

        raise ValueError("No valid JSON-RPC response in SSE stream")

    def _make_jsonrpc_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make a JSON-RPC 2.0 request to the MCP server."""
        self.request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.request_id,
        }

        logger.debug(f"Making JSON-RPC request: {method}")
        try:
            response = self.session.post(
                self.base_url, json=payload, timeout=self.timeout, stream=True
            )
            response.raise_for_status()
            result = self._parse_sse_response(response)
            logger.debug(f"Request {method} succeeded")
            return result
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout after {self.timeout}s")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request failed: {e}")
            raise

    def get_tools(self) -> Dict[str, Any]:
        """List all available tools from the MCP server."""
        result = self._make_jsonrpc_request("tools/list")

        # Validate response structure
        if not isinstance(result, dict):
            raise ValueError(f"Expected dict response, got {type(result)}")

        tools = result.get("tools", [])
        if not isinstance(tools, list):
            raise ValueError(f"Expected tools to be a list, got {type(tools)}")

        # Enforce limit to prevent memory exhaustion
        if len(tools) > MAX_TOOLS_PER_SERVER:
            logger.warning(
                f"Server returned {len(tools)} tools, truncating to {MAX_TOOLS_PER_SERVER}"
            )
            result["tools"] = tools[:MAX_TOOLS_PER_SERVER]

        logger.info(f"Retrieved {len(tools)} tools from server")
        return result

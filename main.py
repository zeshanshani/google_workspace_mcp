"""
Gmail MCP server entry point.

Runs FastMCP's streamable-http transport in OAuth 2.1 + stateless mode.
Enforces those defaults at startup so misconfigured deploys fail loudly.
"""

import argparse
import logging
import os
import socket
import sys

from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(dotenv_path=dotenv_path)

# This build requires OAuth 2.1 + stateless mode. Set the env vars before any
# other module reads them so oauth_config picks them up on first import.
os.environ.setdefault("MCP_ENABLE_OAUTH21", "true")
os.environ.setdefault("WORKSPACE_MCP_STATELESS_MODE", "true")

from auth.oauth_config import reload_oauth_config  # noqa: E402
from auth.scopes import set_enabled_tools  # noqa: E402
from core.log_formatter import EnhancedLogFormatter, configure_file_logging  # noqa: E402
from core.server import server, set_transport_mode, configure_server_for_http  # noqa: E402
from core.tool_tier_loader import resolve_tools_from_tier  # noqa: E402
from core.tool_registry import (  # noqa: E402
    set_enabled_tools as set_enabled_tool_names,
    wrap_server_tool_method,
    filter_server_tools,
)

# Suppress library logs that leak bearer tokens via URL-logging at INFO level.
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

reload_oauth_config()

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

configure_file_logging()

for _handler in logging.root.handlers:
    if isinstance(_handler, logging.StreamHandler) and _handler.stream.name in (
        "<stderr>",
        "<stdout>",
    ):
        _handler.setFormatter(EnhancedLogFormatter(use_colors=True))


def main() -> None:
    parser = argparse.ArgumentParser(description="Gmail MCP Server")
    parser.add_argument(
        "--tool-tier",
        choices=["core", "extended", "complete"],
        default=os.getenv("TOOL_TIER", "core"),
        help="Gmail tool tier to expose (default: core).",
    )
    args = parser.parse_args()

    port = int(os.getenv("PORT", os.getenv("WORKSPACE_MCP_PORT", 8000)))
    host = os.getenv("WORKSPACE_MCP_HOST", "0.0.0.0")
    display_url = os.getenv("WORKSPACE_EXTERNAL_URL") or f"http://{host}:{port}"

    logger.info("Gmail MCP server starting")
    logger.info("  URL: %s", display_url)
    logger.info("  OAuth callback: %s/oauth2callback", display_url)
    logger.info("  Tool tier: %s", args.tool_tier)

    try:
        tier_tools, _services = resolve_tools_from_tier(args.tool_tier, ["gmail"])
    except Exception as exc:
        logger.error("Failed to resolve tool tier %r: %s", args.tool_tier, exc)
        sys.exit(1)

    set_enabled_tool_names(set(tier_tools))
    wrap_server_tool_method(server)
    set_enabled_tools(["gmail"])

    import gmail.gmail_tools  # noqa: F401 — registers tools via @server.tool decorators

    filter_server_tools(server)
    set_transport_mode("streamable-http")
    configure_server_for_http()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
    except OSError as exc:
        logger.error("Cannot bind %s:%s — %s", host, port, exc)
        sys.exit(1)

    logger.info("Ready for MCP connections on %s:%s", host, port)

    try:
        server.run(
            transport="streamable-http",
            host=host,
            port=port,
            stateless_http=True,
        )
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
        sys.exit(0)
    except Exception as exc:
        logger.error("Server error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

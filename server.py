"""Entry point: python -m gittool.server [--project PATH]

Runs the gittool MCP server over stdio, connected to a real Engine.
"""
import argparse
import asyncio
import os
import sys

from gittool.engine import Engine
from gittool.mcp_front import build_server


def main():
    ap = argparse.ArgumentParser(description="gittool v3 MCP server")
    ap.add_argument("--project", default=os.getcwd(),
                    help="Path to the project root (default: cwd)")
    args = ap.parse_args()

    project = os.path.abspath(args.project)
    if not os.path.isdir(project):
        print(f"Error: {project} is not a directory", file=sys.stderr)
        sys.exit(1)

    engine = Engine(project)
    server = build_server(engine)

    # FastMCP (both v1 and v2) has run_stdio_async
    asyncio.run(server.run_stdio_async())


if __name__ == "__main__":
    main()

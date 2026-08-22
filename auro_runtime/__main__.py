"""
CLI entrypoint: python -m auro_runtime run --directive <id> "request"
MCP server: python -m auro_runtime mcp [--transport stdio|streamable-http]
"""

import argparse
import json
import os
import sys
from pathlib import Path

from auro_runtime.orchestrator import run as orchestrator_run


def main():
    parser = argparse.ArgumentParser(description="Directive-Policy Bound Orchestrator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a directive with a user request")
    run_parser.add_argument("--directive", "-d", required=True, help="Directive ID (e.g. file_analysis)")
    run_parser.add_argument("request", nargs="?", default="", help="User request (or read from stdin)")
    run_parser.add_argument("--directives-dir", type=Path, default=None, help="Directives directory")
    run_parser.add_argument("--policies-dir", type=Path, default=None, help="Policies directory")
    run_parser.add_argument("--max-steps", type=int, default=20, help="Max orchestration steps")
    run_parser.add_argument("--json", action="store_true", help="Output full result as JSON")

    mcp_parser = subparsers.add_parser("mcp", help="Start the MCP server (default: stdio for Claude Desktop)")
    mcp_parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport: stdio (default) for local clients, streamable-http for MCP Inspector or remote.",
    )
    mcp_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address when using streamable-http (default: 127.0.0.1). Use 0.0.0.0 only with TLS and auth.",
    )
    mcp_parser.add_argument(
        "--port",
        type=int,
        default=8001,
        help="Port when using streamable-http (default: 8001).",
    )
    mcp_parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help=(
            "Explicit writable MCP workspace. Equivalent to setting "
            "AURO_WORKSPACE_ROOT before startup."
        ),
    )
    mcp_parser.add_argument(
        "--public-url",
        default=None,
        help=(
            "Externally reachable base URL for streamable-http auth metadata. "
            "Required when binding a non-loopback host."
        ),
    )

    args = parser.parse_args()

    if args.command == "mcp":
        if args.workspace is not None:
            os.environ["AURO_WORKSPACE_ROOT"] = str(args.workspace)
        from auro_runtime import mcp_server
        try:
            mcp_server.require_explicit_workspace()
        except RuntimeError as exc:
            mcp_parser.error(str(exc))
        if args.transport == "stdio":
            mcp_server.create_stdio_server().run(transport="stdio")
        else:
            if not mcp_server._MCP_API_KEY:
                print("ERROR: AURO_MCP_API_KEY must be set for streamable-http transport.", file=sys.stderr)
                sys.exit(1)
            if not mcp_server._MCP_API_KEY.isascii():
                # The header arrives decoded as latin-1 and the environment is
                # decoded by the OS. Outside ASCII those two disagree, so a
                # non-ASCII key would start a listener whose token comparison can
                # never match -- an auth control that reads as working and admits
                # nobody. Refuse the key rather than serve the empty gate.
                print("ERROR: AURO_MCP_API_KEY must be ASCII.", file=sys.stderr)
                sys.exit(1)
            public_url = args.public_url
            if public_url is None:
                if args.host not in {"127.0.0.1", "localhost", "::1"}:
                    mcp_parser.error(
                        "--public-url is required when streamable-http binds a non-loopback host"
                    )
                public_url = f"http://localhost:{args.port}"
            server = mcp_server.create_authenticated_server(public_url)
            server.settings.host = args.host
            server.settings.port = args.port
            server.run(transport="streamable-http")
        return

    if args.command == "run":
        request = args.request
        if not request and not sys.stdin.isatty():
            request = sys.stdin.read().strip()
        if not request:
            run_parser.error("Provide a request as argument or via stdin")
        result = orchestrator_run(
            args.directive,
            request,
            directives_dir=args.directives_dir,
            policies_dir=args.policies_dir,
            max_steps=args.max_steps,
        )
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            if result.get("error"):
                print(f"Error: {result['error']}", file=sys.stderr)
            if result.get("final_summary"):
                print(result["final_summary"])
            if result.get("legacy_steps") and not args.json:
                for i, step in enumerate(result["legacy_steps"], 1):
                    print(f"\nStep {i}: {step['tool']}({step.get('args', {})}) — {step.get('reason', '')}")
                    if step.get("error"):
                        print(f"  Error: {step['error']}")
        sys.exit(0 if result.get("success") else 1)

    parser.parse_args(["--help"])


if __name__ == "__main__":
    main()

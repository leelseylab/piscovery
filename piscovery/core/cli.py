import argparse
import asyncio
import sys

from .. import __version__
from .models import Config


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        prog="piscovery",
        description="Pre-engagement reconnaissance tool for web application pentesting",
    )
    parser.add_argument("target", help="Target IP address or hostname (optionally with scheme)")
    parser.add_argument("--no-port-scan", action="store_true", default=False, help="Disable nmap port scanning")
    parser.add_argument("--model", default="gpt-4o", help="LLM model name (default: gpt-4o)")
    parser.add_argument("--api-key", required=True, help="LLM API key")
    parser.add_argument("--api-base", default="https://api.openai.com/v1", help="LLM API base URL")
    parser.add_argument("-H", "--header", action="append", default=[], help="Extra HTTP header (format: 'Key: Value'), can be repeated")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent browser/request workers (default: 5)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--llm-timeout", type=int, default=120, help="LLM request timeout in seconds (default: 120)")
    parser.add_argument("--render-wait", type=int, default=0, help="Extra ms to wait after page load for hydration (default: 0)")
    parser.add_argument(
        "-o", "--output", default="",
        help="JSON report path (default: ~/.piscovery/<target>_<UTC-timestamp>.json)",
    )
    parser.add_argument("--nmap-args", default="", help="Extra nmap arguments (e.g. '-p 1-1000 -sC')")

    parser.add_argument("--scan-budget", type=int, default=1800, help="Total scan wall-clock budget in seconds, 0 = unlimited (default: 1800)")
    parser.add_argument("--path-depth-limit", type=int, default=12, help="Reject URLs whose path has more than N segments (default: 12)")
    parser.add_argument("--query-variants", type=int, default=3, help="Max URLs visited per (path, query-key-set) signature (default: 3)")
    parser.add_argument("--no-resource-blocking", action="store_true", default=False, help="Disable blocking of font/image/media requests in browser")
    parser.add_argument("--click-discovery", action="store_true", default=False, help="Enable active click-based URL discovery (opt-in: clicks safe-filtered buttons)")
    parser.add_argument("--max-clicks", type=int, default=6, help="Max clickable elements explored per page when --click-discovery is set (default: 6)")
    parser.add_argument("--max-response-bytes", type=int, default=5 * 1024 * 1024, help="Drop response bodies larger than this many bytes (default: 5 MiB)")
    parser.add_argument("--max-endpoint-analyses", type=int, default=20, help="Max endpoints to analyse with LLM individually (0 = disable, capture only) (default: 20)")
    parser.add_argument("--endpoint-body-limit", type=int, default=4096, help="Max bytes captured per XHR/fetch response body (default: 4096)")

    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Show per-URL crawl + LLM progress lines")
    parser.add_argument("-V", "--version", action="version", version=f"piscovery {__version__}")

    args = parser.parse_args()

    for name, value in (
        ("--scan-budget", args.scan_budget),
        ("--path-depth-limit", args.path_depth_limit),
        ("--query-variants", args.query_variants),
        ("--max-clicks", args.max_clicks),
        ("--max-response-bytes", args.max_response_bytes),
        ("--max-endpoint-analyses", args.max_endpoint_analyses),
        ("--endpoint-body-limit", args.endpoint_body_limit),
        ("--max-depth", args.max_depth),
        ("--max-pages", args.max_pages),
        ("--concurrency", args.concurrency),
        ("--timeout", args.timeout),
        ("--llm-timeout", args.llm_timeout),
        ("--render-wait", args.render_wait),
    ):
        if value < 0:
            parser.error(f"{name} must be non-negative (got {value})")

    headers: dict = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    return Config(
        target=args.target,
        port_scan=not args.no_port_scan,
        llm_model=args.model,
        llm_api_key=args.api_key,
        llm_base_url=args.api_base,
        headers=headers,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        timeout=args.timeout,
        llm_timeout=args.llm_timeout,
        output_file=args.output,
        nmap_args=args.nmap_args,
        render_wait=args.render_wait,
        scan_budget=args.scan_budget,
        path_depth_limit=args.path_depth_limit,
        query_variants_limit=args.query_variants,
        block_heavy_resources=not args.no_resource_blocking,
        click_discovery=args.click_discovery,
        max_clicks_per_page=args.max_clicks,
        max_response_bytes=args.max_response_bytes,
        max_endpoint_analyses=args.max_endpoint_analyses,
        endpoint_body_limit=args.endpoint_body_limit,
        verbose=args.verbose,
    )


def cli() -> None:
    from .orchestrator import run

    try:
        sys.exit(asyncio.run(run(parse_args())))
    except KeyboardInterrupt:
        print("\n\033[93mInterrupted.\033[0m")
        sys.exit(130)

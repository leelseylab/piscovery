import asyncio
import json
import time
from collections import deque
from typing import Callable, Optional

from playwright.async_api import Browser

from ..core.models import Config, PageInfo, RenderType
from ..core.url import is_in_scope, normalise_url
from .chrome import BrowserManager
from .limits import SignatureCounter, is_path_too_deep
from .parse import extract_routes
from .render import render
from .sitemap import fetch_robots, fetch_sitemap, fetch_url


async def _discover_csr_routes(config: Config, page: PageInfo) -> list:
    routes: set = set()
    for script_url in page.scripts[:10]:
        if not is_in_scope(script_url, config.target_url):
            continue
        _, _, _, js_body = await fetch_url(script_url, config)
        if not js_body:
            continue
        for route in extract_routes(js_body):
            full = normalise_url(config.target_url, route)
            if is_in_scope(full, config.target_url):
                routes.add(full)
    return sorted(routes)


async def _fetch_manifest_urls(config: Config, manifest_url: str) -> list:
    if not manifest_url:
        return []
    if not is_in_scope(manifest_url, config.target_url):
        return []
    status, _, _, body = await fetch_url(manifest_url, config)
    if status != 200 or not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []

    out: list = []
    for key in ("start_url", "scope"):
        val = data.get(key)
        if isinstance(val, str) and val:
            out.append(val)
    for shortcut in data.get("shortcuts", []) or []:
        if isinstance(shortcut, dict):
            url = shortcut.get("url")
            if isinstance(url, str) and url:
                out.append(url)
    return out


async def _render_page(
    browser: Browser,
    config: Config,
    url: str,
    depth: int,
    semaphore: asyncio.Semaphore,
) -> Optional[PageInfo]:
    async with semaphore:
        return await render(browser, url, config, depth)


async def crawl(
    config: Config,
    progress_cb: Optional[Callable[[PageInfo], None]] = None,
    browser: Optional[Browser] = None,
) -> tuple[list, list, dict]:
    own_browser = browser is None
    bm: Optional[BrowserManager] = None
    if own_browser:
        bm = BrowserManager()
        await bm.__aenter__()
        browser = bm.browser
    assert browser is not None

    try:
        return await _crawl_with_browser(browser, config, progress_cb)
    finally:
        if own_browser and bm is not None:
            await bm.__aexit__(None, None, None)


def _budget_exceeded(start: float, budget: int) -> bool:
    return budget > 0 and (time.monotonic() - start) >= budget


async def _crawl_with_browser(
    browser: Browser,
    config: Config,
    progress_cb: Optional[Callable[[PageInfo], None]],
) -> tuple[list, list, dict]:
    render_concurrency = max(1, min(config.concurrency, 4))
    semaphore = asyncio.Semaphore(render_concurrency)

    visited: set = set()
    pages: list = []
    queue: deque = deque([(config.target_url, 0)])
    csr_scanned_scripts: set = set()
    signatures = SignatureCounter(config.query_variants_limit)

    disallowed, sm_urls = await fetch_robots(config)
    robots_info = {"disallowed": disallowed, "sitemaps": sm_urls}

    sitemap_urls = await fetch_sitemap(config, sm_urls)
    for su in sitemap_urls:
        normalised = normalise_url(config.target_url, su)
        if is_in_scope(normalised, config.target_url):
            queue.append((normalised, 1))

    start = time.monotonic()

    def _admit(url: str, depth: int) -> Optional[tuple]:
        if url in visited:
            return None
        if depth > config.max_depth:
            return None
        if is_path_too_deep(url, config.path_depth_limit):
            return None
        if signatures.see(url):
            return None
        visited.add(url)
        return (url, depth)

    while queue and len(pages) < config.max_pages:
        if _budget_exceeded(start, config.scan_budget):
            break

        batch: list = []
        while queue and len(batch) < render_concurrency:
            raw_url, depth = queue.popleft()
            url = normalise_url(config.target_url, raw_url)
            admitted = _admit(url, depth)
            if admitted is not None:
                batch.append(admitted)

        if not batch:
            break

        tasks = [
            _render_page(browser, config, url, depth, semaphore)
            for url, depth in batch
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception) or result is None:
                continue

            pages.append(result)
            if progress_cb is not None:
                progress_cb(result)

            if result.render_type == RenderType.CSR:
                scripts_key = frozenset(result.scripts[:10])
                if scripts_key not in csr_scanned_scripts:
                    csr_scanned_scripts.add(scripts_key)
                    csr_routes = await _discover_csr_routes(config, result)
                    for route in csr_routes:
                        if route not in visited:
                            queue.append((route, result.depth + 1))

            if result.manifest_url:
                manifest_links = await _fetch_manifest_urls(config, result.manifest_url)
                for raw in manifest_links:
                    full = normalise_url(config.target_url, raw)
                    if is_in_scope(full, config.target_url) and full not in visited:
                        queue.append((full, result.depth + 1))

            if result.depth < config.max_depth:
                for link in result.links:
                    if is_in_scope(link, config.target_url) and link not in visited:
                        queue.append((link, result.depth + 1))

    return pages, sitemap_urls, robots_info

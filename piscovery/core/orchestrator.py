import asyncio
import signal
from pathlib import Path

from ..llm import analyse_endpoint, analyse_page
from ..scanner import run_nmap
from ..spider import BrowserManager, crawl
from ..spider.endpoints import group, path_pattern, pick_top
from .models import Config, EndpointReport, PageReport, RenderType, ScanReport
from .preflight import run_preflight
from .report import (
    default_output_path,
    print_banner,
    print_progress,
    print_report,
    save_markdown_report,
    save_report,
)
from .url import strip_target_scheme


_C = "\033[1m\033[96m"
_D = "\033[2m"
_R = "\033[0m"
_RED = "\033[91m"


async def _nmap(config: Config):
    if not config.port_scan:
        return None
    print(f"{_C}[NMAP]{_R} Starting port scan...")
    result = await run_nmap(strip_target_scheme(config.target), config.nmap_args, timeout=300)
    print(f"{_C}[NMAP]{_R} Scan complete: {len(result.open_ports)} open port(s) found")
    return result


async def _spider(config: Config, browser, queue: asyncio.Queue):
    print(f"{_C}[SPIDER]{_R} Starting web crawl...")

    def on_page(page):
        if config.verbose:
            print_progress(page)
        queue.put_nowait(page)

    pages, sitemap_urls, robots_info = await crawl(config, progress_cb=on_page, browser=browser)
    print(f"{_C}[SPIDER]{_R} Crawl complete: {len(pages)} page(s) discovered")
    return pages, sitemap_urls, robots_info


def _form_sig(form):
    parts = []
    for f in form.fields:
        marker = f.name or "(unnamed)"
        if f.required:
            marker += "*"
        marker += f":{f.field_type or 'text'}"
        parts.append(marker)
    return ", ".join(parts)


def _obs(page):
    """Flatten one PageInfo into a list of endpoint observation dicts."""
    out = []

    by_req = {}
    for r in getattr(page, "responses", []) or []:
        by_req.setdefault((r.method.upper(), r.url), r)

    seen = set()
    for ep in getattr(page, "xhr_endpoints", []) or []:
        key = (ep.method.upper(), ep.url)
        seen.add(key)
        r = by_req.get(key)
        out.append({
            "method": ep.method,
            "url": ep.url,
            "post_data": ep.post_data,
            "resource_type": ep.resource_type,
            "status_code": r.status_code if r else 0,
            "response_headers": dict(r.headers) if r else {},
            "response_body_preview": r.body_preview if r else "",
            "response_mime": r.mime if r else "",
            "page_url": page.url,
        })

    for r in getattr(page, "responses", []) or []:
        key = (r.method.upper(), r.url)
        if key in seen:
            continue
        out.append({
            "method": r.method,
            "url": r.url,
            "post_data": "",
            "resource_type": "fetch",
            "status_code": r.status_code,
            "response_headers": dict(r.headers),
            "response_body_preview": r.body_preview,
            "response_mime": r.mime,
            "page_url": page.url,
        })

    for ws in getattr(page, "ws_observations", []) or []:
        out.append({
            "method": "WS",
            "url": ws.url,
            "post_data": (ws.sent_preview or "")[:512],
            "resource_type": "websocket",
            "status_code": ws.close_code or 0,
            "response_headers": {},
            "response_body_preview": (ws.received_preview or "")[:512],
            "response_mime": "",
            "page_url": page.url,
        })

    for form in getattr(page, "forms", []) or []:
        method = (form.method or "GET").upper()
        is_get = method == "GET"
        out.append({
            "method": method,
            "url": form.action,
            "post_data": "" if is_get else f"form fields: {_form_sig(form)}",
            "resource_type": "form-get" if is_get else "form-post",
            "status_code": 0,
            "response_headers": {},
            "response_body_preview": "",
            "response_mime": "",
            "page_url": page.url,
        })

    for hint in getattr(page, "static_endpoint_hints", []) or []:
        out.append({
            "method": hint.get("method", "GET"),
            "url": hint.get("url", ""),
            "post_data": "",
            "resource_type": hint.get("resource_type", "js-static"),
            "status_code": 0,
            "response_headers": {},
            "response_body_preview": "",
            "response_mime": "",
            "page_url": page.url,
        })

    return out


def _keys(observations):
    out, seen = [], set()
    for o in observations:
        if not o.get("url"):
            continue
        k = f"{(o.get('method') or 'GET').upper()} {path_pattern(o['url'])}"
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


async def _consumer(config, queue, reports, observations, stop):
    while True:
        try:
            page = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            if stop.is_set() and queue.empty():
                break
            continue

        analysis = await analyse_page(config, page)
        if config.verbose:
            tag = "done" if analysis.category else "fail"
            print(f"  {_D}[llm]{_R} {tag}: {page.url}")

        ob = _obs(page)
        observations.extend(ob)
        reports.append(PageReport(page=page, analysis=analysis, triggered_endpoint_keys=_keys(ob)))
        queue.task_done()


async def _analyse_eps(config, observations):
    if not observations:
        return []

    print(f"{_C}[ENDPOINTS]{_R} Aggregating {len(observations)} observation(s)...")
    grouped = group(observations)
    print(f"{_C}[ENDPOINTS]{_R} {len(grouped)} unique endpoint(s) after dedup")

    if config.max_endpoint_analyses <= 0:
        return [EndpointReport(endpoint=ep, analysis=None) for ep in grouped]

    chosen = pick_top(grouped, config.max_endpoint_analyses)
    chosen_keys = {(ep.method, ep.url) for ep in chosen}
    print(f"{_C}[ENDPOINTS]{_R} Running LLM analysis on top {len(chosen)} endpoint(s)...")

    sem = asyncio.Semaphore(min(config.concurrency, 3))

    async def run_one(ep):
        async with sem:
            a = await analyse_endpoint(config, ep)
            if config.verbose:
                tag = "done" if a.role else "fail"
                print(f"  {_D}[ep-llm]{_R} {tag}: {ep.method} {ep.url}")
            return EndpointReport(endpoint=ep, analysis=a)

    done = await asyncio.gather(*[run_one(ep) for ep in chosen], return_exceptions=True)
    out = [r for r in done if not isinstance(r, Exception)]
    for ep in grouped:
        if (ep.method, ep.url) not in chosen_keys:
            out.append(EndpointReport(endpoint=ep, analysis=None))
    return out


async def run(config: Config) -> int:
    print_banner()

    bm = BrowserManager()
    try:
        await bm.__aenter__()
    except Exception as e:
        msg = str(e).splitlines()[0] if str(e) else type(e).__name__
        print(f"  {_RED}[FAIL]{_R}  Browser launch failed: {msg}")
        return 1

    try:
        if not await run_preflight(config, chrome_ready=True):
            return 1

        queue = asyncio.Queue()
        reports, observations = [], []
        stop = asyncio.Event()

        workers = min(config.concurrency, 3)
        print(f"{_C}[LLM]{_R} {workers} analysis worker(s) with {config.llm_model}\n")

        consumers = [
            asyncio.create_task(_consumer(config, queue, reports, observations, stop))
            for _ in range(workers)
        ]

        nmap_result = None
        sitemap_urls = []
        robots_info = {}

        loop = asyncio.get_running_loop()

        def on_signal():
            if not stop.is_set():
                print(f"\n{_D}Interrupt received — cleaning up...{_R}")
                stop.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, on_signal)
            except NotImplementedError:
                pass

        try:
            nmap_result, (_pages, sitemap_urls, robots_info) = await asyncio.gather(
                _nmap(config),
                _spider(config, bm.browser, queue),
            )
        finally:
            stop.set()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.remove_signal_handler(sig)
                except (NotImplementedError, ValueError):
                    pass

        try:
            await asyncio.wait_for(asyncio.gather(*consumers), timeout=max(60, config.llm_timeout * 2))
        except asyncio.TimeoutError:
            print(f"  {_D}[llm]{_R} consumer timeout — cancelling")
            for c in consumers:
                c.cancel()
            await asyncio.gather(*consumers, return_exceptions=True)

        endpoint_reports = await _analyse_eps(config, observations)
    finally:
        await bm.__aexit__(None, None, None)

    reports.sort(key=lambda r: (r.page.depth, r.page.url))

    techs = set()
    rt = RenderType.UNKNOWN
    for pr in reports:
        techs.update(pr.page.technologies)
        if pr.page.depth == 0:
            rt = pr.page.render_type

    report = ScanReport(
        target=config.target,
        target_url=config.target_url,
        render_type=rt,
        technologies=sorted(techs),
        nmap=nmap_result,
        sitemap_urls=sitemap_urls,
        robots_info=robots_info,
        pages=reports,
        endpoints=endpoint_reports,
    )

    print_report(report)

    out_path = config.output_file or str(default_output_path(config.target))
    save_report(report, out_path)
    save_markdown_report(report, str(Path(out_path).with_suffix(".md")))
    return 0

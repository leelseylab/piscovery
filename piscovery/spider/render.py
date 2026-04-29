import asyncio
import re

from playwright.async_api import (
    Browser,
    Error as PlaywrightError,
    TimeoutError as PlaywrightTimeoutError,
)

from ..core.models import (
    Config,
    PageInfo,
    ResponseObservation,
    WebSocketObservation,
    XHREndpoint,
)
from ..core.url import extract_params
from .discovery import HISTORY_API_SHIM, click_walk, frame_links, history_urls
from .parse import (
    PageHTMLParser,
    detect_render_type,
    detect_technologies,
    extract_endpoints,
    extract_sw,
    parse_cookies,
)


_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

_BLOCK_RT = {"font", "image", "media"}
_OBSERVED_RT = {"xhr", "fetch", "eventsource"}
_BODY_MIMES = (
    "application/json",
    "application/x-ndjson",
    "application/ld+json",
    "text/",
    "application/javascript",
    "application/xml",
    "application/graphql",
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def _redact(text):
    return _JWT_RE.sub("[REDACTED:JWT]", text)


def _body_capturable(mime):
    if not mime:
        return False
    low = mime.lower()
    return any(low.startswith(p) for p in _BODY_MIMES) or "+json" in low


async def _block_heavy(route):
    try:
        if route.request.resource_type in _BLOCK_RT:
            await route.abort()
            return
    except PlaywrightError:
        pass
    try:
        await route.continue_()
    except PlaywrightError:
        pass


async def render(browser: Browser, url: str, config: Config, depth: int = 0):
    try:
        return await asyncio.wait_for(_run(browser, url, config, depth), timeout=config.timeout + 10)
    except asyncio.TimeoutError:
        return None


async def _run(browser, url, config, depth):
    ctx = await browser.new_context(
        user_agent=_UA,
        ignore_https_errors=True,
        extra_http_headers=dict(config.headers),
    )

    try:
        try:
            await ctx.add_init_script(HISTORY_API_SHIM)
        except PlaywrightError:
            pass

        if config.block_heavy_resources:
            try:
                await ctx.route("**/*", _block_heavy)
            except PlaywrightError:
                pass

        page = await ctx.new_page()

        xhrs = []
        responses = []
        ws_obs = []
        budget = {"used": 0}
        total_cap = config.endpoint_body_total_cap if config.endpoint_body_total_cap > 0 else None

        def on_request(req):
            if req.resource_type not in _OBSERVED_RT:
                return
            try:
                pd = req.post_data or ""
            except Exception:
                pd = ""
            xhrs.append(XHREndpoint(
                url=req.url,
                method=req.method,
                resource_type=req.resource_type,
                post_data=pd[:config.endpoint_body_limit],
            ))

        page.on("request", on_request)

        async def on_response(resp):
            try:
                if resp.request.resource_type not in _OBSERVED_RT:
                    return
                try:
                    headers = {k.lower(): v for k, v in (await resp.all_headers()).items()}
                except PlaywrightError:
                    headers = {}
                mime = (headers.get("content-type") or "").split(";")[0].strip().lower()
                preview = ""
                if _body_capturable(mime) and (total_cap is None or budget["used"] < total_cap):
                    try:
                        body = await resp.body()
                    except PlaywrightError:
                        body = b""
                    if body:
                        chunk = body[:config.endpoint_body_limit]
                        preview = _redact(chunk.decode("utf-8", errors="replace"))
                        budget["used"] += len(chunk)
                responses.append(ResponseObservation(
                    url=resp.url,
                    method=resp.request.method,
                    status_code=resp.status,
                    headers=headers,
                    mime=mime,
                    body_preview=preview,
                ))
            except Exception:
                pass

        page.on("response", on_response)

        def on_ws(ws):
            obs = WebSocketObservation(url=ws.url)
            ws_obs.append(obs)
            sent = {"left": 1024}
            recv = {"left": 1024}

            def payload_of(p):
                return p.get("payload") if isinstance(p, dict) else p

            def record(payload, b, attr):
                if not isinstance(payload, str) or b["left"] <= 0:
                    return
                chunk = payload[:b["left"]]
                b["left"] -= len(chunk)
                cur = getattr(obs, attr) or ""
                setattr(obs, attr, (cur + _redact(chunk))[:1024])

            ws.on("framesent", lambda p: record(payload_of(p), sent, "sent_preview"))
            ws.on("framereceived", lambda p: record(payload_of(p), recv, "received_preview"))

            def closed(*args):
                obs.closed = True
                if args and isinstance(args[0], int):
                    obs.close_code = args[0]

            ws.on("close", closed)

        try:
            page.on("websocket", on_ws)
        except (PlaywrightError, AttributeError):
            pass

        status = 0
        resp_headers = {}
        raw_html = ""
        rendered = ""
        cookies = []

        response = None
        try:
            response = await page.goto(url, timeout=config.timeout * 1000, wait_until="load")
        except PlaywrightTimeoutError:
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=config.timeout * 1000)
            except PlaywrightTimeoutError:
                pass
        except PlaywrightError:
            return None

        if config.render_wait > 0:
            try:
                await page.wait_for_timeout(config.render_wait)
            except PlaywrightError:
                pass

        if response is not None:
            status = response.status
            try:
                resp_headers = {k.lower(): v for k, v in (await response.all_headers()).items()}
            except PlaywrightError:
                resp_headers = {}
            try:
                body = await response.body()
                if len(body) > config.max_response_bytes > 0:
                    raw_html = ""
                else:
                    raw_html = body.decode("utf-8", errors="replace")
            except PlaywrightError:
                raw_html = ""

        try:
            rendered = await page.content()
        except PlaywrightError:
            rendered = ""

        try:
            jar = await ctx.cookies([url])
            cookies = [f"{c['name']}={c['value']}" for c in jar]
        except PlaywrightError:
            cookies = []

        hist = await history_urls(page, url)
        frames = await frame_links(page, url)
        clicks = await click_walk(page, config, url)
    finally:
        try:
            await ctx.close()
        except PlaywrightError:
            pass

    if status == 0 and not rendered and not raw_html:
        return None

    if not cookies:
        cookies = parse_cookies(resp_headers)

    html = rendered or raw_html
    p = PageHTMLParser(url)
    try:
        p.feed(html)
    except Exception:
        pass

    seen = set(p.links)
    for src in (hist, frames, clicks, p.preload_hints):
        for link in src:
            if link not in seen:
                seen.add(link)
                p.links.append(link)

    req_headers = {"User-Agent": _UA, **config.headers}

    hints = extract_endpoints(html)
    for sw_url in extract_sw(html):
        hints.append({"method": "GET", "url": sw_url, "resource_type": "service-worker"})

    return PageInfo(
        url=url,
        depth=depth,
        status_code=status,
        title=p.title,
        render_type=detect_render_type(raw_html, rendered),
        technologies=detect_technologies(html, resp_headers),
        forms=p.forms,
        links=p.links,
        scripts=p.scripts,
        parameters=extract_params(url),
        request_headers=req_headers,
        response_headers=resp_headers,
        meta_tags=p.meta_tags,
        cookies=cookies,
        content_length=len(html),
        raw_html=raw_html,
        rendered_html=rendered,
        xhr_endpoints=xhrs,
        responses=responses,
        ws_observations=ws_obs,
        static_endpoint_hints=hints,
        manifest_url=p.manifest_url,
    )

import asyncio
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

from ..core.models import Config
from ..core.url import normalise_url


USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


async def fetch_url(url: str, config: Config) -> tuple[int, dict, dict, str]:
    ctx = ssl.create_default_context()
    req_headers = {"User-Agent": USER_AGENT}
    req_headers.update(config.headers)
    parsed = urlparse(url)
    req_headers.setdefault("Host", parsed.netloc)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        resp = await asyncio.to_thread(
            urllib.request.urlopen, req, timeout=config.timeout, context=ctx
        )
        body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, req_headers, resp_headers, body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, req_headers, {k.lower(): v for k, v in e.headers.items()}, body
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, req_headers, {}, ""


async def fetch_robots(config: Config) -> tuple[list, list]:
    url = normalise_url(config.target_url, "/robots.txt")
    status, _, _, body = await fetch_url(url, config)
    disallowed: list = []
    sitemaps: list = []
    if status != 200 or not body:
        return disallowed, sitemaps
    for line in body.splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif low.startswith("sitemap:"):
            idx = line.index(":") + 1
            sm = line[idx:].strip()
            if sm:
                sitemaps.append(sm)
    return disallowed, sitemaps


async def fetch_sitemap(config: Config, urls: list | None = None) -> list:
    found: list = []
    to_check = list(urls) if urls else [normalise_url(config.target_url, "/sitemap.xml")]

    checked: set = set()
    for sm_url in to_check[:5]:
        if sm_url in checked:
            continue
        checked.add(sm_url)
        status, _, _, body = await fetch_url(sm_url, config)
        if status != 200 or not body:
            continue
        for match in re.finditer(r"<loc>\s*(.*?)\s*</loc>", body, re.IGNORECASE):
            loc = match.group(1).strip()
            if loc.endswith(".xml") and loc not in checked:
                checked.add(loc)
                sub_status, _, _, sub_body = await fetch_url(loc, config)
                if sub_status == 200 and sub_body:
                    for sub_match in re.finditer(r"<loc>\s*(.*?)\s*</loc>", sub_body, re.IGNORECASE):
                        found.append(sub_match.group(1).strip())
            else:
                found.append(loc)
    return found

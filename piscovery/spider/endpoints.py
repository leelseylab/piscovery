import re
from urllib.parse import urlparse, urlunparse

from ..core.models import EndpointInfo


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUM = re.compile(r"^\d+$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,}$")
_HAS_DIGIT = re.compile(r"\d")
_HAS_ALPHA = re.compile(r"[A-Za-z]")

_INTERESTING = re.compile(
    r"^/(api|v\d+|graphql|auth|login|admin|user|account|order|payment|"
    r"register|signup|signin|logout|password|token|session)",
    re.IGNORECASE,
)


def path_pattern(url: str) -> str:
    p = urlparse(url)
    out = []
    for seg in p.path.split("/"):
        if not seg:
            out.append(seg)
        elif _UUID.match(seg):
            out.append("{uuid}")
        elif _NUM.match(seg):
            out.append("{id}")
        elif _TOKEN.match(seg) and _HAS_DIGIT.search(seg) and _HAS_ALPHA.search(seg):
            out.append("{token}")
        else:
            out.append(seg)
    new_path = "/".join(out)
    if p.query:
        keys = sorted({kv.split("=", 1)[0] for kv in p.query.split("&") if kv})
        query = "&".join(f"{k}=" for k in keys)
    else:
        query = ""
    return urlunparse((p.scheme, p.netloc, new_path, "", query, ""))


_AUTHY = ("set-cookie", "authorization", "www-authenticate")


def score(ep: EndpointInfo) -> float:
    s = 0.0
    if ep.method.upper() in {"POST", "PUT", "DELETE", "PATCH"}:
        s += 3
    if ep.post_data:
        s += 2
    if 400 <= ep.status_code < 600:
        s += 1
    if _INTERESTING.match(urlparse(ep.url).path):
        s += 2
    if any(h in {k.lower() for k in ep.response_headers} for h in _AUTHY):
        s += 1
    if ep.resource_type == "websocket":
        s += 1
    return s


def _better(cur: EndpointInfo, cand: dict) -> bool:
    cur_body = bool(cur.response_body_preview)
    cand_body = bool(cand.get("response_body_preview"))
    if cand_body != cur_body:
        return cand_body
    cur_diag = 400 <= cur.status_code < 600
    cand_diag = 400 <= cand.get("status_code", 0) < 600
    if cand_diag != cur_diag:
        return cand_diag
    return True


def group(observations) -> list:
    """Dedupe raw observations by (method, path_pattern). Returns EndpointInfo list."""
    groups = {}
    for obs in observations:
        method = (obs.get("method") or "GET").upper()
        url = obs.get("url") or ""
        if not url:
            continue
        key = (method, path_pattern(url))
        if key not in groups:
            groups[key] = EndpointInfo(
                url=key[1],
                raw_url_samples=[url],
                method=method,
                resource_type=obs.get("resource_type") or "",
                post_data=obs.get("post_data") or "",
                status_code=obs.get("status_code") or 0,
                response_headers=dict(obs.get("response_headers") or {}),
                response_body_preview=obs.get("response_body_preview") or "",
                response_mime=obs.get("response_mime") or "",
                observed_on_pages=[obs["page_url"]] if obs.get("page_url") else [],
                sample_count=1,
            )
            continue

        ep = groups[key]
        ep.sample_count += 1
        if url not in ep.raw_url_samples and len(ep.raw_url_samples) < 3:
            ep.raw_url_samples.append(url)
        pg = obs.get("page_url")
        if pg and pg not in ep.observed_on_pages:
            ep.observed_on_pages.append(pg)

        if _better(ep, obs):
            ep.status_code = obs.get("status_code") or ep.status_code
            if obs.get("response_headers"):
                ep.response_headers = dict(obs["response_headers"])
            if obs.get("response_body_preview"):
                ep.response_body_preview = obs["response_body_preview"]
            if obs.get("response_mime"):
                ep.response_mime = obs["response_mime"]
            if obs.get("post_data"):
                ep.post_data = obs["post_data"]
            if obs.get("resource_type"):
                ep.resource_type = obs["resource_type"]

    for ep in groups.values():
        ep.interest_score = score(ep)
    return list(groups.values())


_NON_GET = ("POST", "PUT", "DELETE", "PATCH")


def pick_top(eps, limit: int) -> list:
    if limit <= 0 or not eps:
        return []

    out, taken = [], set()
    by_score = sorted(eps, key=lambda e: e.interest_score, reverse=True)

    def _key(e):
        return (e.method, e.url)

    # Stratification floor: each non-GET method gets up to 3, WS/SSE up to 2.
    for method in _NON_GET:
        n = 0
        for ep in by_score:
            if n >= 3 or len(out) >= limit:
                break
            if ep.method.upper() == method and _key(ep) not in taken:
                out.append(ep)
                taken.add(_key(ep))
                n += 1

    for rt in ("websocket", "eventsource"):
        n = 0
        for ep in by_score:
            if n >= 2 or len(out) >= limit:
                break
            if ep.resource_type == rt and _key(ep) not in taken:
                out.append(ep)
                taken.add(_key(ep))
                n += 1

    for ep in by_score:
        if len(out) >= limit:
            break
        if _key(ep) not in taken:
            out.append(ep)
            taken.add(_key(ep))
    return out

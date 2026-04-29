from urllib.parse import urljoin, urlparse, urlunparse


def normalise_url(base: str, href: str) -> str:
    joined = urljoin(base, href)
    parsed = urlparse(joined)
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))


def strip_target_scheme(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        return host
    return target


def is_in_scope(url: str, target: str) -> bool:
    target_parsed = urlparse(target)
    url_parsed = urlparse(url)
    if url_parsed.scheme not in ("http", "https"):
        return False
    return url_parsed.netloc == target_parsed.netloc


def extract_params(url: str) -> dict:
    parsed = urlparse(url)
    params: dict = {}
    if not parsed.query:
        return params
    for part in parsed.query.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            params[k] = v
        else:
            params[part] = ""
    return params

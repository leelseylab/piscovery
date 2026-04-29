from urllib.parse import parse_qs, urlparse


def is_path_too_deep(url: str, limit: int) -> bool:
    if limit <= 0:
        return False
    path = urlparse(url).path
    segments = [s for s in path.split("/") if s]
    return len(segments) > limit


def signature_key(url: str) -> tuple:
    parsed = urlparse(url)
    keys = frozenset(parse_qs(parsed.query, keep_blank_values=True).keys())
    return (parsed.path, keys)


class SignatureCounter:
    def __init__(self, limit: int):
        self.limit = limit
        self._counts: dict = {}

    def see(self, url: str) -> bool:
        if self.limit <= 0:
            return False
        key = signature_key(url)
        count = self._counts.get(key, 0) + 1
        self._counts[key] = count
        return count > self.limit

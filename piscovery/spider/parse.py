import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from ..core.models import FormField, FormInfo, RenderType
from ..core.url import normalise_url


CSR_INDICATORS = {
    "react": [
        r"data-reactroot", r"__NEXT_DATA__", r"_next/",
        r"react\.production", r"react-dom",
    ],
    "vue": [
        r"data-v-[a-f0-9]", r"__vue__", r"vue\.runtime",
        r"nuxt", r"__NUXT__",
    ],
    "angular": [
        r"ng-version", r"_nghost", r"_ngcontent",
        r"angular\.io", r"ng-app",
    ],
    "svelte": [
        r"__svelte", r"svelte-",
    ],
}

ROUTE_PATTERNS = [
    r"""(?:path|route)\s*[:=]\s*['"](/[^'"]*?)['"]""",
    r"""<Route[^>]*path\s*=\s*["']([^"']+)["']""",
    r"""(?:to|href)\s*[:=]\s*['"](/[^'"]*?)['"]""",
    r"""router\.\w+\s*\(\s*['"](/[^'"]*?)['"]""",
]


# JS endpoint call patterns — extract (method, url) tuples.
# (None, url) means method couldn't be statically determined; default to GET later.
ENDPOINT_PATTERNS = [
    # fetch('...') with optional 2nd arg containing method
    (r"""fetch\(\s*['"`]([^'"`]+)['"`](?:\s*,\s*\{[^}]*?method\s*:\s*['"`](\w+)['"`])?""", "url_then_method"),
    # axios.get/.post/.put/.delete/.patch/.head('...')
    (r"""axios\.(get|post|put|delete|patch|head)\s*\(\s*['"`]([^'"`]+)['"`]""", "method_then_url"),
    # axios({ method: 'POST', url: '...' })
    (r"""axios\(\s*\{[^}]*?method\s*:\s*['"`](\w+)['"`][^}]*?url\s*:\s*['"`]([^'"`]+)['"`]""", "method_then_url"),
    # jQuery $.get / $.post / $.ajax
    (r"""\$\.(get|post|put|delete|ajax)\s*\(\s*['"`]([^'"`]+)['"`]""", "method_then_url"),
    # XMLHttpRequest open
    (r"""\.open\s*\(\s*['"`](\w+)['"`]\s*,\s*['"`]([^'"`]+)['"`]""", "method_then_url"),
    # WebSocket / EventSource constructors
    (r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""", "ws_url"),
    (r"""new\s+EventSource\s*\(\s*['"`]([^'"`]+)['"`]""", "sse_url"),
]


SW_REGISTRATION_RE = re.compile(
    r"""serviceWorker\s*\.\s*register\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

TECH_HEADERS = {
    "server": None,
    "x-powered-by": None,
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": None,
    "x-cms": None,
}

TECH_PATTERNS = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"Joomla", "Joomla"),
    (r"Drupal", "Drupal"),
    (r"laravel", "Laravel"),
    (r"django", "Django"),
    (r"express", "Express.js"),
    (r"flask", "Flask"),
    (r"spring", "Spring"),
    (r"rails", "Ruby on Rails"),
    (r"jquery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
    (r"tailwind", "Tailwind CSS"),
    (r"graphql", "GraphQL"),
    (r"swagger|openapi", "OpenAPI/Swagger"),
]

HTML_CONTENT_TYPES = (
    "text/html", "application/xhtml+xml", "application/xhtml",
)


_DATA_LINK_ATTRS = ("data-href", "data-url", "data-link")
_NON_NAV_PREFIXES = ("javascript:", "mailto:", "tel:", "#", "data:")


class PageHTMLParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.title = ""
        self.links: list = []
        self.forms: list = []
        self.scripts: list = []
        self.meta_tags: dict = {}
        self.manifest_url: str = ""
        self.preload_hints: list = []
        self._in_title = False
        self._current_form: FormInfo | None = None
        self._title_data: list = []
        self._seen_links: set = set()

    def _add_link(self, href: str) -> None:
        if not href or href.startswith(_NON_NAV_PREFIXES):
            return
        full = normalise_url(self.base_url, href)
        if full in self._seen_links:
            return
        self._seen_links.add(full)
        self.links.append(full)

    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = dict(attrs)

        for data_attr in _DATA_LINK_ATTRS:
            if data_attr in attr_dict:
                self._add_link(attr_dict[data_attr])

        if tag == "title":
            self._in_title = True
            self._title_data = []

        elif tag == "a":
            self._add_link(attr_dict.get("href", ""))

        elif tag == "area":
            self._add_link(attr_dict.get("href", ""))

        elif tag == "link":
            rel = attr_dict.get("rel", "").lower().strip()
            href = attr_dict.get("href", "")
            if not href:
                pass
            elif rel in ("canonical", "alternate"):
                self._add_link(href)
            elif rel == "manifest":
                self.manifest_url = normalise_url(self.base_url, href)
            elif rel in ("preload", "prefetch"):
                self.preload_hints.append(normalise_url(self.base_url, href))

        elif tag == "form":
            action = attr_dict.get("action", self.base_url)
            if not action.startswith("http"):
                action = normalise_url(self.base_url, action)
            self._current_form = FormInfo(
                action=action,
                method=attr_dict.get("method", "GET").upper(),
                enctype=attr_dict.get("enctype", ""),
            )

        elif tag in ("input", "textarea", "select"):
            if self._current_form is not None:
                self._current_form.fields.append(FormField(
                    name=attr_dict.get("name", ""),
                    field_type=attr_dict.get("type", "text"),
                    value=attr_dict.get("value", ""),
                    placeholder=attr_dict.get("placeholder", ""),
                    required="required" in attr_dict,
                ))

        elif tag == "script":
            src = attr_dict.get("src", "")
            if src:
                if not src.startswith("http"):
                    src = urljoin(self.base_url, src)
                self.scripts.append(src)

        elif tag == "meta":
            name = attr_dict.get("name", attr_dict.get("property", ""))
            content = attr_dict.get("content", "")
            if name and content:
                self.meta_tags[name] = content

    def handle_endtag(self, tag: str):
        if tag == "title":
            self._in_title = False
            self.title = "".join(self._title_data).strip()
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str):
        if self._in_title:
            self._title_data.append(data)


def detect_technologies(html: str, headers: dict) -> list:
    techs: set = set()
    for hdr, label in TECH_HEADERS.items():
        val = headers.get(hdr, "")
        if val:
            techs.add(label or val)

    for pattern, name in TECH_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            techs.add(name)

    for framework, patterns in CSR_INDICATORS.items():
        for p in patterns:
            if re.search(p, html, re.IGNORECASE):
                techs.add(framework.capitalize())
                break

    techs.discard(None)
    return sorted(techs)


def detect_render_type(raw_html: str, rendered_html: str) -> RenderType:
    if not rendered_html:
        return RenderType.UNKNOWN

    raw_text_len = len(re.sub(r"<[^>]+>", "", raw_html))
    rendered_text_len = len(re.sub(r"<[^>]+>", "", rendered_html))

    has_csr_framework = False
    for patterns in CSR_INDICATORS.values():
        for p in patterns:
            if re.search(p, raw_html, re.IGNORECASE):
                has_csr_framework = True
                break
        if has_csr_framework:
            break

    if has_csr_framework:
        if raw_text_len == 0 or rendered_text_len > raw_text_len * 1.5:
            return RenderType.CSR
        return RenderType.SSR

    raw_link_count = len(re.findall(r"<a\s", raw_html, re.IGNORECASE))
    rendered_link_count = len(re.findall(r"<a\s", rendered_html, re.IGNORECASE))
    if rendered_link_count > raw_link_count * 2 and rendered_link_count > 5:
        return RenderType.CSR

    if raw_link_count > 3 or raw_text_len > 1000:
        return RenderType.SSR

    return RenderType.STATIC


def extract_routes(js: str) -> list:
    routes = set()
    for pat in ROUTE_PATTERNS:
        for m in re.finditer(pat, js, re.IGNORECASE):
            r = m.group(1)
            if r and not r.startswith("//"):
                routes.add(r)
    return sorted(routes)


def extract_endpoints(js: str) -> list:
    """Pull endpoint hints out of JS source. Returns dicts of {method, url, resource_type}."""
    out, seen = [], set()

    def push(method, url, rt="js-static"):
        if not url or url.startswith(("//", "data:", "javascript:")):
            return
        m = (method or "GET").upper()
        k = (m, url, rt)
        if k in seen:
            return
        seen.add(k)
        out.append({"method": m, "url": url, "resource_type": rt})

    for pat, kind in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, js, re.IGNORECASE):
            g = m.groups()
            if kind == "url_then_method":
                push(g[1] if len(g) > 1 and g[1] else "GET", g[0])
            elif kind == "method_then_url":
                push(g[0], g[1] if len(g) > 1 else "")
            elif kind == "ws_url":
                push("WS", g[0] if g else "", "websocket")
            elif kind == "sse_url":
                push("GET", g[0] if g else "", "eventsource")
    return out


def extract_sw(js: str) -> list:
    return [m.group(1) for m in SW_REGISTRATION_RE.finditer(js)]


def is_html(headers: dict) -> bool:
    ct = headers.get("content-type", "")
    return not ct or any(t in ct.lower() for t in HTML_CONTENT_TYPES)


def parse_cookies(headers: dict) -> list:
    cookies: list = []
    raw = headers.get("set-cookie", "")
    if not raw:
        return cookies
    for part in re.split(r",\s*(?=[A-Za-z_\-]+=)", raw):
        part = part.strip()
        if not part:
            continue
        cookie_pair = part.split(";")[0].strip()
        if "=" in cookie_pair:
            cookies.append(cookie_pair)
    return cookies

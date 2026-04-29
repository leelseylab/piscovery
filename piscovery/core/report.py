import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .. import __version__
from .models import PageInfo, ScanReport


_OUTPUT_DIR = Path.home() / ".piscovery"


def _safe_target(target: str) -> str:
    if "://" in target:
        target = target.split("://", 1)[1]
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", target).strip("_")
    return cleaned or "target"


def default_output_path(target: str) -> Path:
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe = _safe_target(target)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = _OUTPUT_DIR / f"{safe}_{ts}.json"
    if not candidate.exists():
        return candidate
    for i in range(1, 1000):
        candidate = _OUTPUT_DIR / f"{safe}_{ts}_{i:03d}.json"
        if not candidate.exists():
            return candidate
    raise RuntimeError("output file collision counter exhausted")


_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_CYAN = "\033[96m"
_MAGENTA = "\033[95m"
_WHITE = "\033[97m"

_SEP = f"{_DIM}{'─' * 72}{_RESET}"
_DSEP = f"{_DIM}{'═' * 72}{_RESET}"


def print_banner() -> None:
    banner = f"""{_CYAN}{_BOLD}
    ┌─────────────────────────────────────────┐
    │         Piscovery v{__version__:<21}│
    │   Pre-engagement Reconnaissance Tool    │
    └─────────────────────────────────────────┘{_RESET}
"""
    print(banner)


def print_progress(page: PageInfo) -> None:
    status = page.status_code
    colour = _GREEN if 200 <= status < 400 else _YELLOW if status < 500 else _RED
    print(
        f"  {_DIM}[crawl]{_RESET} {colour}{status}{_RESET} "
        f"{page.url} {_DIM}({page.render_type.value}){_RESET}"
    )


def _short_path(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return path


def print_report(report: ScanReport) -> None:
    print(f"\n{_DSEP}")
    print(f"{_BOLD}{_WHITE}  SCAN REPORT: {report.target}{_RESET}")
    print(f"  URL: {report.target_url}")
    print(f"  {_DIM}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{_RESET}")
    print(_DSEP)

    if report.nmap and report.nmap.open_ports:
        print(f"\n{_BOLD}{_CYAN}[PORT SCAN]{_RESET}")
        print(_SEP)
        for port in report.nmap.open_ports:
            svc = report.nmap.services.get(port, "unknown")
            print(f"  {_GREEN}{port:>10}{_RESET}  {svc}")
        if report.nmap.os_detection:
            print(f"\n  OS: {report.nmap.os_detection}")
        print()

    if report.technologies:
        print(f"{_BOLD}{_CYAN}[TECHNOLOGIES]{_RESET}")
        print(_SEP)
        print(f"  {', '.join(report.technologies)}")
        print()

    if report.robots_info:
        disallowed = report.robots_info.get("disallowed", [])
        if disallowed:
            print(f"{_BOLD}{_CYAN}[ROBOTS.TXT]{_RESET}")
            print(_SEP)
            for path in disallowed:
                print(f"  {_YELLOW}Disallow{_RESET}: {path}")
            print()

    if report.sitemap_urls:
        print(f"{_BOLD}{_CYAN}[SITEMAP]{_RESET}")
        print(_SEP)
        for url in report.sitemap_urls[:20]:
            print(f"  {url}")
        if len(report.sitemap_urls) > 20:
            print(f"  {_DIM}... and {len(report.sitemap_urls) - 20} more{_RESET}")
        print()

    print(f"{_BOLD}{_CYAN}[SITE MAP]{_RESET}")
    print(_SEP)
    max_path_len = 40
    for pr in report.pages:
        path = _short_path(pr.page.url)
        cat = ""
        if pr.analysis and pr.analysis.category:
            cat = pr.analysis.category
        status = pr.page.status_code
        colour = _GREEN if 200 <= status < 400 else _YELLOW
        pad = max(2, max_path_len - len(path))
        dots = "·" * pad
        print(f"  {colour}{status}{_RESET} {path} {_DIM}{dots}{_RESET} {_WHITE}{cat}{_RESET}")
    print()

    print(f"{_BOLD}{_CYAN}[PAGE ANALYSIS] ({len(report.pages)} pages){_RESET}")
    print(_DSEP)

    for i, pr in enumerate(report.pages, 1):
        page = pr.page
        analysis = pr.analysis
        path = _short_path(page.url)

        cat_label = ""
        if analysis and analysis.category:
            cat_label = f" — {analysis.category}"

        print(f"\n{_BOLD}{_WHITE}  [{i}] {path}{cat_label}{_RESET}")

        status_colour = _GREEN if 200 <= page.status_code < 400 else _YELLOW
        print(f"  {status_colour}{page.status_code}{_RESET} "
              f"{page.render_type.value}  "
              f"{page.title or ''}")

        if page.technologies:
            print(f"  Tech: {_DIM}{', '.join(page.technologies)}{_RESET}")

        if analysis and analysis.description:
            print(f"\n  {_BOLD}Function:{_RESET}")
            for line in analysis.description.split("\n"):
                print(f"    {line}")

        if page.forms:
            print(f"\n  {_BOLD}Forms:{_RESET}")
            for fi, form in enumerate(page.forms, 1):
                print(f"    {_MAGENTA}Form {fi}{_RESET}: "
                      f"{form.method} -> {form.action}")
                if form.enctype:
                    print(f"      enctype: {form.enctype}")
                for fld in form.fields:
                    req = " *" if fld.required else ""
                    val = f" = {fld.value}" if fld.value else ""
                    print(f"      - {fld.name or '(unnamed)'} "
                          f"[{fld.field_type}]{req}{val}")

        if page.parameters:
            print(f"\n  {_BOLD}URL Parameters:{_RESET}")
            for k, v in page.parameters.items():
                print(f"    {k} = {v or '(empty)'}")

        if page.xhr_endpoints:
            print(f"\n  {_BOLD}XHR/Fetch Endpoints:{_RESET}")
            seen = set()
            for ep in page.xhr_endpoints:
                key = (ep.method, ep.url)
                if key in seen:
                    continue
                seen.add(key)
                rt = f" [{ep.resource_type}]" if ep.resource_type else ""
                print(f"    {_MAGENTA}{ep.method}{_RESET} {ep.url}{_DIM}{rt}{_RESET}")
                if ep.post_data:
                    snippet = ep.post_data[:120].replace("\n", " ")
                    print(f"      body: {_DIM}{snippet}{_RESET}")

        if page.cookies:
            print(f"\n  {_BOLD}Cookies:{_RESET}")
            for c in page.cookies:
                print(f"    {c}")

        _SEC = ("server", "x-powered-by", "x-frame-options",
                "content-security-policy", "strict-transport-security",
                "x-content-type-options", "access-control-allow-origin",
                "set-cookie")
        sec = {k: v for k, v in page.response_headers.items() if k.lower() in _SEC}
        if sec:
            print(f"\n  {_BOLD}Headers:{_RESET}")
            for k, v in sec.items():
                print(f"    {_DIM}{k}{_RESET}: {v}")

        if analysis and analysis.suggestions:
            print(f"\n  {_BOLD}{_YELLOW}Attack Suggestions:{_RESET}")
            for j, s in enumerate(analysis.suggestions, 1):
                print(f"    {_YELLOW}{j}. {s.attack_type}{_RESET}")
                print(f"       Target:  {s.target}")
                print(f"       Why:     {s.reasoning}")
                print(f"       Seen:    {_DIM}{s.observation}{_RESET}")

        print(f"\n{_SEP}")

    if report.endpoints:
        print(f"{_BOLD}{_CYAN}[ENDPOINTS] ({len(report.endpoints)} unique){_RESET}")
        print(_DSEP)

        by_method: dict = {}
        for er in report.endpoints:
            ep = er.endpoint
            if ep is None:
                continue
            by_method.setdefault(ep.method.upper(), []).append(er)

        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "WS"):
            if method not in by_method:
                continue
            entries = sorted(by_method[method], key=lambda e: -e.endpoint.interest_score)
            print(f"\n  {_BOLD}{_MAGENTA}{method}{_RESET} ({len(entries)})")
            for i, er in enumerate(entries, 1):
                ep = er.endpoint
                role = ""
                if er.analysis and er.analysis.role:
                    role = f" — {er.analysis.role}"
                tag = f"{_DIM}{ep.resource_type}{_RESET}" if ep.resource_type else ""
                status = f"{ep.status_code}" if ep.status_code else "-"
                print(f"    {i:>2}. [{status}] {ep.url}{role}  {tag}")
                if er.analysis and er.analysis.description:
                    desc = er.analysis.description.splitlines()[0]
                    if len(desc) > 100:
                        desc = desc[:100] + "..."
                    print(f"        {_DIM}{desc}{_RESET}")
                if er.analysis and er.analysis.suggestions:
                    for s in er.analysis.suggestions[:2]:
                        print(f"        {_YELLOW}→ {s.attack_type}{_RESET}: {s.target}")

        other_methods = [m for m in by_method if m not in ("GET", "POST", "PUT", "PATCH", "DELETE", "WS")]
        for method in sorted(other_methods):
            entries = by_method[method]
            print(f"\n  {_BOLD}{_MAGENTA}{method}{_RESET} ({len(entries)})")
            for i, er in enumerate(entries, 1):
                ep = er.endpoint
                print(f"    {i:>2}. {ep.url}")
        print()

    total_suggestions = sum(
        len(pr.analysis.suggestions)
        for pr in report.pages if pr.analysis
    )
    total_xhr = sum(len(pr.page.xhr_endpoints) for pr in report.pages)
    analysed_endpoints = sum(1 for er in report.endpoints if er.analysis)
    endpoint_suggestions = sum(
        len(er.analysis.suggestions) for er in report.endpoints if er.analysis
    )

    print(f"\n{_DSEP}")
    print(f"{_BOLD}{_WHITE}  SUMMARY{_RESET}")
    print(f"  Pages discovered:        {len(report.pages)}")
    print(f"  XHR/Fetch captured:      {total_xhr}")
    print(f"  Unique endpoints:        {len(report.endpoints)}")
    print(f"  Endpoints LLM-analysed:  {analysed_endpoints}")
    print(f"  Page attack suggestions: {total_suggestions}")
    print(f"  Endpoint suggestions:    {endpoint_suggestions}")
    if report.nmap:
        print(f"  Open ports:              {len(report.nmap.open_ports)}")
    print(_DSEP)
    print()


def save_report(report: ScanReport, path: str) -> None:
    target_path = Path(path).expanduser()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    data: dict = {
        "target": report.target,
        "target_url": report.target_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "render_type": report.render_type.value,
        "technologies": report.technologies,
        "robots_info": report.robots_info,
        "sitemap_urls": report.sitemap_urls,
    }

    if report.nmap:
        nmap_data: dict = {
            "open_ports": report.nmap.open_ports,
            "services": report.nmap.services,
            "os_detection": report.nmap.os_detection,
        }
        raw_xml = report.nmap.raw_output
        if raw_xml and raw_xml != "[nmap timed out]":
            xml_path = target_path.with_suffix(".nmap.xml")
            xml_path.write_text(raw_xml)
            nmap_data["raw_xml_file"] = str(xml_path)
        data["nmap"] = nmap_data

    pages: list = []
    for pr in report.pages:
        page_data: dict = {
            "url": pr.page.url,
            "status_code": pr.page.status_code,
            "title": pr.page.title,
            "render_type": pr.page.render_type.value,
            "technologies": pr.page.technologies,
            "request_headers": pr.page.request_headers,
            "response_headers": pr.page.response_headers,
            "parameters": pr.page.parameters,
            "cookies": pr.page.cookies,
            "forms": [
                {
                    "action": f.action,
                    "method": f.method,
                    "enctype": f.enctype,
                    "fields": [
                        {
                            "name": fld.name,
                            "type": fld.field_type,
                            "value": fld.value,
                            "required": fld.required,
                        }
                        for fld in f.fields
                    ],
                }
                for f in pr.page.forms
            ],
            "xhr_endpoints": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "resource_type": ep.resource_type,
                    "post_data": ep.post_data,
                }
                for ep in pr.page.xhr_endpoints
            ],
            "triggered_endpoint_keys": list(pr.triggered_endpoint_keys),
        }

        if pr.analysis:
            page_data["analysis"] = {
                "category": pr.analysis.category,
                "description": pr.analysis.description,
                "suggestions": [
                    {
                        "attack_type": s.attack_type,
                        "target": s.target,
                        "reasoning": s.reasoning,
                        "observation": s.observation,
                    }
                    for s in pr.analysis.suggestions
                ],
            }

        pages.append(page_data)

    data["pages"] = pages

    endpoints: list = []
    for er in report.endpoints:
        ep = er.endpoint
        if ep is None:
            continue
        ep_data: dict = {
            "url": ep.url,
            "raw_url_samples": list(ep.raw_url_samples),
            "method": ep.method,
            "resource_type": ep.resource_type,
            "post_data": ep.post_data,
            "status_code": ep.status_code,
            "response_headers": ep.response_headers,
            "response_mime": ep.response_mime,
            "response_body_preview": ep.response_body_preview,
            "observed_on_pages": list(ep.observed_on_pages),
            "sample_count": ep.sample_count,
            "interest_score": ep.interest_score,
        }
        if er.analysis:
            ep_data["analysis"] = {
                "role": er.analysis.role,
                "description": er.analysis.description,
                "suggestions": [
                    {
                        "attack_type": s.attack_type,
                        "target": s.target,
                        "reasoning": s.reasoning,
                        "observation": s.observation,
                    }
                    for s in er.analysis.suggestions
                ],
            }
        endpoints.append(ep_data)
    data["endpoints"] = endpoints

    with target_path.open("w") as f:
        json.dump(data, f, indent=2)

    print(f"{_GREEN}Report saved to {target_path}{_RESET}")
    xml_ref = data.get("nmap", {}).get("raw_xml_file")
    if xml_ref:
        print(f"{_GREEN}Nmap XML saved to {xml_ref}{_RESET}")


def _esc(v) -> str:
    if v is None:
        return ""
    return str(v).replace("|", "\\|").replace("\n", " ")


_SEC_KEYS = ("server", "x-powered-by", "x-frame-options",
             "content-security-policy", "strict-transport-security",
             "x-content-type-options", "access-control-allow-origin",
             "set-cookie")


def _sec_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() in _SEC_KEYS}


def save_markdown_report(report: ScanReport, path: str) -> None:
    target_path = Path(path).expanduser()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list = []
    lines.append(f"# piscovery Scan Report — {report.target}")
    lines.append("")
    lines.append(f"- **Target:** `{report.target}`")
    if report.target_url:
        lines.append(f"- **Target URL:** {report.target_url}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- **Render type:** {report.render_type.value}")
    lines.append(f"- **piscovery version:** {__version__}")
    lines.append("")

    if report.nmap and report.nmap.open_ports:
        lines.append("## Port Scan")
        lines.append("")
        lines.append("| Port | Service |")
        lines.append("|------|---------|")
        for port in report.nmap.open_ports:
            svc = report.nmap.services.get(port, "unknown")
            lines.append(f"| `{port}` | {_esc(svc)} |")
        if report.nmap.os_detection:
            lines.append("")
            lines.append(f"**OS detection:** {report.nmap.os_detection}")
        lines.append("")

    if report.technologies:
        lines.append("## Technologies")
        lines.append("")
        lines.append(", ".join(f"`{t}`" for t in report.technologies))
        lines.append("")

    disallowed = (report.robots_info or {}).get("disallowed", [])
    sm_from_robots = (report.robots_info or {}).get("sitemaps", [])
    if disallowed or sm_from_robots:
        lines.append("## robots.txt")
        lines.append("")
        if disallowed:
            lines.append("### Disallowed paths")
            lines.append("")
            for path_entry in disallowed:
                lines.append(f"- `{path_entry}`")
            lines.append("")
        if sm_from_robots:
            lines.append("### Sitemap references")
            lines.append("")
            for sm in sm_from_robots:
                lines.append(f"- {sm}")
            lines.append("")

    if report.sitemap_urls:
        lines.append(f"## Sitemap ({len(report.sitemap_urls)} URLs)")
        lines.append("")
        for url in report.sitemap_urls[:50]:
            lines.append(f"- {url}")
        if len(report.sitemap_urls) > 50:
            lines.append(f"- _… and {len(report.sitemap_urls) - 50} more_")
        lines.append("")

    if report.pages:
        lines.append("## Site Map")
        lines.append("")
        lines.append("| # | Status | Path | Category |")
        lines.append("|---|--------|------|----------|")
        for i, pr in enumerate(report.pages, 1):
            page = pr.page
            cat = ""
            if pr.analysis and pr.analysis.category:
                cat = pr.analysis.category
            lines.append(f"| {i} | {page.status_code} | `{_esc(_short_path(page.url))}` | {_esc(cat)} |")
        lines.append("")

    if report.pages:
        lines.append(f"## Pages ({len(report.pages)})")
        lines.append("")
        for i, pr in enumerate(report.pages, 1):
            page = pr.page
            analysis = pr.analysis
            cat_label = ""
            if analysis and analysis.category:
                cat_label = f" — {analysis.category}"
            lines.append(f"### {i}. `{_short_path(page.url)}`{cat_label}")
            lines.append("")
            lines.append(f"- **URL:** {page.url}")
            lines.append(f"- **Status:** {page.status_code}")
            lines.append(f"- **Render:** {page.render_type.value}")
            if page.title:
                lines.append(f"- **Title:** {_esc(page.title)}")
            if page.technologies:
                lines.append(f"- **Tech:** {', '.join(f'`{t}`' for t in page.technologies)}")
            lines.append("")

            if analysis and analysis.description:
                lines.append("**Function**")
                lines.append("")
                lines.append(analysis.description)
                lines.append("")

            if page.forms:
                lines.append("**Forms**")
                lines.append("")
                for fi, form in enumerate(page.forms, 1):
                    lines.append(f"- Form {fi}: `{form.method}` → `{form.action}`")
                    if form.enctype:
                        lines.append(f"    - enctype: `{form.enctype}`")
                    for fld in form.fields:
                        req = " *required*" if fld.required else ""
                        val = f" = `{fld.value}`" if fld.value else ""
                        lines.append(f"    - `{fld.name or '(unnamed)'}` `[{fld.field_type}]`{req}{val}")
                lines.append("")

            if page.parameters:
                lines.append("**URL Parameters**")
                lines.append("")
                for k, v in page.parameters.items():
                    lines.append(f"- `{k}` = `{v or '(empty)'}`")
                lines.append("")

            if page.xhr_endpoints:
                lines.append("**XHR / Fetch Endpoints**")
                lines.append("")
                seen = set()
                for ep in page.xhr_endpoints:
                    key = (ep.method, ep.url)
                    if key in seen:
                        continue
                    seen.add(key)
                    rt = f" `[{ep.resource_type}]`" if ep.resource_type else ""
                    lines.append(f"- `{ep.method}` {ep.url}{rt}")
                    if ep.post_data:
                        snippet = ep.post_data[:200].replace("\n", " ")
                        lines.append(f"    - body: `{_esc(snippet)}`")
                lines.append("")

            if page.cookies:
                lines.append("**Cookies**")
                lines.append("")
                for c in page.cookies:
                    lines.append(f"- `{c}`")
                lines.append("")

            sec = _sec_headers(page.response_headers or {})
            if sec:
                lines.append("**Response Headers (notable)**")
                lines.append("")
                for k, v in sec.items():
                    lines.append(f"- `{k}`: {_esc(v)}")
                lines.append("")

            if analysis and analysis.suggestions:
                lines.append("**Attack Suggestions**")
                lines.append("")
                for j, s in enumerate(analysis.suggestions, 1):
                    lines.append(f"{j}. **{s.attack_type}** — target: `{s.target}`")
                    if s.reasoning:
                        lines.append(f"    - **Why:** {s.reasoning}")
                    if s.observation:
                        lines.append(f"    - **Seen:** {s.observation}")
                lines.append("")

            if pr.triggered_endpoint_keys:
                lines.append("**Triggered Endpoints**")
                lines.append("")
                for key in pr.triggered_endpoint_keys:
                    lines.append(f"- `{key}`")
                lines.append("")

            lines.append("---")
            lines.append("")

    if report.endpoints:
        lines.append(f"## Endpoints ({len(report.endpoints)} unique)")
        lines.append("")
        by_method: dict = {}
        for er in report.endpoints:
            ep = er.endpoint
            if ep is None:
                continue
            by_method.setdefault(ep.method.upper(), []).append(er)

        method_order = ["GET", "POST", "PUT", "PATCH", "DELETE", "WS"]
        ordered_methods = [m for m in method_order if m in by_method] + [
            m for m in sorted(by_method) if m not in method_order
        ]

        for method in ordered_methods:
            entries = sorted(by_method[method], key=lambda e: -e.endpoint.interest_score)
            lines.append(f"### {method} ({len(entries)})")
            lines.append("")
            for i, er in enumerate(entries, 1):
                ep = er.endpoint
                role_tag = ""
                if er.analysis and er.analysis.role:
                    role_tag = f" — {er.analysis.role}"
                status_tag = f" `[status {ep.status_code}]`" if ep.status_code else ""
                lines.append(f"#### {method} {i}. `{ep.url}`{role_tag}{status_tag}")
                lines.append("")
                meta = []
                if ep.resource_type:
                    meta.append(f"resource_type: `{ep.resource_type}`")
                meta.append(f"sample_count: {ep.sample_count}")
                if ep.response_mime:
                    meta.append(f"mime: `{ep.response_mime}`")
                meta.append(f"score: {ep.interest_score:.1f}")
                lines.append("- " + " · ".join(meta))
                if ep.observed_on_pages:
                    lines.append(f"- **Observed on:** {', '.join(ep.observed_on_pages[:5])}")
                if len(ep.raw_url_samples) > 1:
                    samples = ", ".join(f"`{s}`" for s in ep.raw_url_samples)
                    lines.append(f"- **Sample URLs:** {samples}")
                if ep.post_data:
                    snippet = ep.post_data[:300].replace("\n", " ")
                    lines.append(f"- **Request body sample:** `{_esc(snippet)}`")
                if ep.response_body_preview:
                    snippet = ep.response_body_preview[:400].replace("\n", " ")
                    lines.append(f"- **Response body preview:** `{_esc(snippet)}`")
                lines.append("")

                if er.analysis and er.analysis.description:
                    lines.append(er.analysis.description)
                    lines.append("")
                if er.analysis and er.analysis.suggestions:
                    lines.append("**Attack Points**")
                    lines.append("")
                    for j, s in enumerate(er.analysis.suggestions, 1):
                        lines.append(f"{j}. **{s.attack_type}** — target: `{s.target}`")
                        if s.reasoning:
                            lines.append(f"    - **Why:** {s.reasoning}")
                        if s.observation:
                            lines.append(f"    - **Seen:** {s.observation}")
                    lines.append("")
            lines.append("")

    total_suggestions = sum(
        len(pr.analysis.suggestions) for pr in report.pages if pr.analysis
    )
    total_xhr = sum(len(pr.page.xhr_endpoints) for pr in report.pages)
    analysed_endpoints = sum(1 for er in report.endpoints if er.analysis)
    endpoint_suggestions = sum(
        len(er.analysis.suggestions) for er in report.endpoints if er.analysis
    )

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Pages discovered: **{len(report.pages)}**")
    lines.append(f"- XHR/Fetch captured: **{total_xhr}**")
    lines.append(f"- Unique endpoints: **{len(report.endpoints)}**")
    lines.append(f"- Endpoints LLM-analysed: **{analysed_endpoints}**")
    lines.append(f"- Page attack suggestions: **{total_suggestions}**")
    lines.append(f"- Endpoint suggestions: **{endpoint_suggestions}**")
    if report.nmap:
        lines.append(f"- Open ports: **{len(report.nmap.open_ports)}**")
    lines.append("")

    target_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"{_GREEN}Markdown report saved to {target_path}{_RESET}")

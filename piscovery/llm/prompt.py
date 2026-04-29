import json
import re
from urllib.parse import urlparse

from ..core.models import AttackSuggestion, LLMAnalysis, PageInfo


_BODY_EXCERPT_LIMIT = 8000


SYSTEM_PROMPT = """You are a penetration tester preparing for an engagement.
You are reviewing HTTP packet captures of a target web application to understand what each page does and where to focus your testing.

Your job:
1. Identify the PAGE FUNCTION — what is this page? (e.g. bulletin board, login form, user profile, search, file upload, admin dashboard, API endpoint, data table with CRUD, shopping cart, etc.)
2. Suggest PRACTICAL ATTACKS based on the function — what would you try during the pentest and why?

Base your suggestions on what you actually observe in the packet data:
- Forms with user input fields → what kind of injection or abuse fits this input?
- URL parameters → reflected attacks, parameter tampering, IDOR
- File upload forms → unrestricted upload, path traversal
- Search functionality → reflected XSS, SQLi via search query
- User-generated content displayed to others → stored XSS
- Authentication flows → brute force, credential stuffing, session fixation
- Numeric IDs in URLs → IDOR, enumeration
- API endpoints in scripts → direct API abuse, auth bypass
- XHR/Fetch endpoints → backend API attack surface, auth/IDOR/mass assignment
- Missing security headers → clickjacking, MIME sniffing
- Cookie flags → session hijacking

Be specific. Not "there might be XSS" but "the post body textarea at /board/write submits user HTML via POST, which is rendered on /board/view — try Stored XSS".

Respond ONLY with valid JSON:
{
  "category": "Page function in 2-3 words (e.g. Bulletin Board, Login Page, User Profile, File Manager)",
  "description": "One paragraph explaining what this page does and how users interact with it",
  "suggestions": [
    {
      "attack_type": "Attack name (e.g. Stored XSS, SQLi, IDOR, SSRF, Reflected XSS, File Upload Bypass)",
      "target": "Specific element — which form, parameter, endpoint, or header",
      "reasoning": "Why this attack applies to THIS page function (because it is a bulletin board that displays user content, because this parameter is passed in the URL, etc.)",
      "observation": "What you saw in the packet data that led to this suggestion (the form field, the parameter, the header, the inline script variable)"
    }
  ]
}"""


def _extract_html_comments(html: str) -> list:
    return re.findall(r"<!--(.*?)-->", html, re.DOTALL)


def _extract_inline_scripts(html: str) -> list:
    return re.findall(r"<script(?:\s[^>]*)?>(.+?)</script>", html, re.DOTALL | re.IGNORECASE)


def _build_body_excerpt(page: PageInfo) -> str:
    html = page.rendered_html or page.raw_html
    if not html:
        return "(empty body)"

    parts: list = []

    comments = _extract_html_comments(html)
    if comments:
        meaningful = [c.strip() for c in comments if len(c.strip()) > 3]
        if meaningful:
            parts.append("--- HTML Comments ---")
            for c in meaningful[:20]:
                parts.append(f"  <!-- {c[:300]} -->")

    inline_scripts = _extract_inline_scripts(html)
    if inline_scripts:
        parts.append("--- Inline Scripts ---")
        for i, script in enumerate(inline_scripts[:10], 1):
            trimmed = script.strip()[:800]
            if trimmed:
                parts.append(f"  <script #{i}>")
                parts.append(f"    {trimmed}")

    used = sum(len(p) for p in parts)
    remaining = _BODY_EXCERPT_LIMIT - used
    if remaining > 500:
        clean = re.sub(r"<script(?:\s[^>]*)?>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        clean = re.sub(r"<style(?:\s[^>]*)?>.*?</style>", "", clean, flags=re.DOTALL | re.IGNORECASE)
        if len(clean) > remaining:
            parts.append(f"--- Response Body ({len(html)} chars, showing first {remaining}) ---")
            parts.append(clean[:remaining])
        else:
            parts.append(f"--- Response Body ({len(html)} chars) ---")
            parts.append(clean)
    elif html:
        parts.append(f"--- Response Body ({len(html)} chars, truncated) ---")
        parts.append(html[:500])

    return "\n".join(parts)


def _build_page_summary(page: PageInfo) -> str:
    parts: list = []
    parsed = urlparse(page.url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    parts.append("========== HTTP REQUEST ==========")
    parts.append(f"GET {path} HTTP/1.1")
    for k, v in page.request_headers.items():
        parts.append(f"{k}: {v}")

    parts.append("")
    parts.append("========== HTTP RESPONSE ==========")
    parts.append(f"HTTP/1.1 {page.status_code}")
    for k, v in page.response_headers.items():
        parts.append(f"{k}: {v}")

    parts.append("")
    parts.append("========== RESPONSE BODY ==========")
    parts.append(_build_body_excerpt(page))

    parts.append("")
    parts.append("========== EXTRACTED DATA ==========")
    if page.title:
        parts.append(f"Title: {page.title}")
    parts.append(f"Render Type: {page.render_type.value}")

    if page.technologies:
        parts.append(f"Technologies: {', '.join(page.technologies)}")

    if page.cookies:
        parts.append(f"Cookies: {', '.join(page.cookies)}")

    if page.forms:
        parts.append("Forms:")
        for i, form in enumerate(page.forms, 1):
            parts.append(f"  Form {i}: action={form.action} method={form.method}")
            if form.enctype:
                parts.append(f"    enctype={form.enctype}")
            for fld in form.fields:
                attrs = f"name={fld.name} type={fld.field_type}"
                if fld.value:
                    attrs += f" value={fld.value}"
                if fld.required:
                    attrs += " required"
                if fld.placeholder:
                    attrs += f" placeholder={fld.placeholder}"
                parts.append(f"    Field: {attrs}")

    if page.parameters:
        parts.append(f"URL Parameters: {json.dumps(page.parameters)}")

    if page.meta_tags:
        parts.append("Meta Tags:")
        for k, v in page.meta_tags.items():
            parts.append(f"  {k}: {v}")

    if page.links:
        shown = page.links[:30]
        parts.append(f"Links ({len(page.links)} total, showing first {len(shown)}):")
        for link in shown:
            parts.append(f"  {link}")

    if page.scripts:
        parts.append(f"External Scripts: {', '.join(page.scripts[:15])}")

    if page.xhr_endpoints:
        seen = set()
        unique = []
        for ep in page.xhr_endpoints:
            key = (ep.method, ep.url)
            if key in seen:
                continue
            seen.add(key)
            unique.append(ep)
        parts.append(f"XHR/Fetch Endpoints ({len(unique)} unique):")
        for ep in unique[:30]:
            line = f"  {ep.method} {ep.url}"
            if ep.resource_type:
                line += f" [{ep.resource_type}]"
            parts.append(line)
            if ep.post_data:
                snippet = ep.post_data[:200].replace("\n", " ")
                parts.append(f"    body: {snippet}")

    return "\n".join(parts)


def _parse_analysis(raw: str) -> LLMAnalysis:
    analysis = LLMAnalysis(raw_response=raw)
    clean = raw.strip()
    if clean.startswith("```"):
        lines = clean.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        clean = "\n".join(lines)

    try:
        data = json.loads(clean)
    except json.JSONDecodeError:
        analysis.description = raw
        return analysis

    analysis.category = data.get("category", "")
    analysis.description = data.get("description", "")

    for s in data.get("suggestions", []):
        analysis.suggestions.append(AttackSuggestion(
            attack_type=s.get("attack_type", ""),
            target=s.get("target", ""),
            reasoning=s.get("reasoning", ""),
            observation=s.get("observation", ""),
        ))

    return analysis

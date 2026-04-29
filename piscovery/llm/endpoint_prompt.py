import json

from ..core.models import AttackSuggestion, EndpointAnalysis, EndpointInfo


SYSTEM_PROMPT = """You are reviewing a single backend HTTP (or WebSocket) endpoint observed during web reconnaissance.

Your job:
1. Identify the endpoint's ROLE — what does it do? (e.g. "User registration", "Authentication login", "Search query", "Order CRUD", "Real-time chat channel", "Webhook receiver", "File upload", "Token issuance")
2. Pinpoint specific ATTACK POINTS for the engagement based on what you actually see (method, request body shape, response body, status, headers, originating page).

Be concrete:
- POST taking JSON body → mass assignment, type juggling, JSON injection, prototype pollution
- Path with numeric/UUID id → IDOR, enumeration
- Search/query parameter → SQLi, NoSQLi, reflected XSS, command injection
- Auth/login → brute force, credential stuffing, user enumeration via timing/error
- File upload → path traversal, content-type bypass, polyglot, RCE via processing
- Token/session issuance → JWT none-alg, weak secret, replay, missing rotation
- Endpoint accepts URL param → SSRF, open redirect
- WebSocket → auth at handshake, frame injection, missing rate limit
- 4xx/5xx response → misconfig, default error verbose, stack trace leak
- Missing security headers in response → clickjacking on related page, MIME sniffing
- Set-Cookie without Secure/HttpOnly/SameSite → session hijack, CSRF

Respond ONLY with valid JSON:
{
  "role": "Short role label (2-4 words)",
  "description": "One paragraph explaining what this endpoint does, when it's called, and what it likely talks to",
  "suggestions": [
    {
      "attack_type": "SQLi | IDOR | SSRF | Mass Assignment | Auth Bypass | XSS | Path Traversal | Insecure Deserialisation | JWT none-alg | etc.",
      "target": "Specific parameter, header, path segment, or body field",
      "reasoning": "Why this attack applies given what you see",
      "observation": "What in the captured data led to this — name the field/header/value/status/etc."
    }
  ]
}"""


_NOTABLE_HEADERS = (
    "server", "x-powered-by", "set-cookie", "www-authenticate",
    "content-security-policy", "x-frame-options", "strict-transport-security",
    "access-control-allow-origin", "content-type",
)


def _summary(ep: EndpointInfo) -> str:
    out = ["========== ENDPOINT ==========", f"{ep.method} {ep.url}"]

    if ep.raw_url_samples:
        out.append(f"Sample URLs ({len(ep.raw_url_samples)}):")
        out += [f"  {s}" for s in ep.raw_url_samples]
    if ep.resource_type:
        out.append(f"Resource type: {ep.resource_type}")
    out.append(f"Sample count: {ep.sample_count}")
    if ep.observed_on_pages:
        out.append(f"Observed on pages ({len(ep.observed_on_pages)}):")
        out += [f"  {p}" for p in ep.observed_on_pages[:5]]

    out += ["", "========== REQUEST =========="]
    if ep.post_data:
        body = ep.post_data
        if len(body) > 1500:
            body = body[:1500] + " ...[truncated]"
        out.append(body)
    else:
        out.append("(no request body / GET-equivalent)")

    out += ["", "========== RESPONSE =========="]
    if ep.status_code:
        out.append(f"HTTP {ep.status_code}  {ep.response_mime or ''}")
    else:
        out.append("(response not captured — endpoint inferred from JS or form action)")

    for k, v in ep.response_headers.items():
        if k.lower() in _NOTABLE_HEADERS:
            out.append(f"{k}: {v}")

    if ep.response_body_preview:
        body = ep.response_body_preview
        if len(body) > 2500:
            body = body[:2500] + " ...[truncated]"
        out += ["", f"Body preview ({len(ep.response_body_preview)} chars):", body]

    return "\n".join(out)


def _parse(raw: str) -> EndpointAnalysis:
    a = EndpointAnalysis(raw_response=raw)
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        a.description = raw
        return a

    a.role = data.get("role", "")
    a.description = data.get("description", "")
    for s in data.get("suggestions", []):
        a.suggestions.append(AttackSuggestion(
            attack_type=s.get("attack_type", ""),
            target=s.get("target", ""),
            reasoning=s.get("reasoning", ""),
            observation=s.get("observation", ""),
        ))
    return a

# Piscovery

Pre-engagement reconnaissance tool for web application pentesting. Automates initial target discovery — crawling, technology detection, and attack surface mapping — so you can focus on actual testing.

**Piscovery does not perform any active exploitation.** It identifies what *could* be tested and *why*, reducing manual recon time.

## Features

- Parallel nmap port scanning + web crawling
- Playwright-driven Chromium rendering (handles CSR/SPA frameworks)
- **Live XHR/fetch endpoint capture** — backend API surface that static crawlers miss
- Automatic sitemap and robots.txt discovery
- CSR route extraction (React Router, Vue Router, Angular, etc.)
- Technology fingerprinting from headers, HTML, and scripts
- LLM-powered page analysis with vulnerability predictions
- OpenAI-compatible API (works with any provider)

## Requirements

- Python 3.10+
- [nmap](https://nmap.org/) (for port scanning)
- Google Chrome (system install — Playwright reuses it via `channel="chrome"`)
- An OpenAI-compatible LLM API key

## Installation

```bash
pip install -e .
```

This pulls `playwright` as a dependency. Piscovery uses your **system Chrome** by default, so you do **not** need to run `playwright install chromium` unless you want a sandboxed browser.

## Usage

### Basic scan

```bash
piscovery 192.168.1.100 --api-key sk-your-key
```

### Full options

```bash
piscovery 10.0.0.1 \
  --api-key sk-your-key \
  --model gpt-4o \
  --api-base https://api.openai.com/v1 \
  --max-depth 3 \
  --max-pages 50 \
  --concurrency 5 \
  --timeout 30 \
  --render-wait 1500 \
  -H "Authorization: Bearer token123" \
  -H "Cookie: session=abc" \
  --nmap-args "-p 1-10000 -sC" \
  --no-port-scan \
  -o report.json
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target IP or hostname (required) | — |
| `-h, --help` | Show help message and exit | — |
| `--no-port-scan` | Skip nmap scanning | `false` |
| `--model` | LLM model name | `gpt-4o` |
| `--api-key` | LLM API key (required) | — |
| `--api-base` | LLM API base URL | `https://api.openai.com/v1` |
| `-H, --header` | Extra HTTP header (`Key: Value`), repeatable | — |
| `--max-depth` | Max crawl depth | `3` |
| `--max-pages` | Max pages to crawl | `50` |
| `--concurrency` | Parallel workers (browser contexts capped at 4) | `5` |
| `--timeout` | Request timeout (seconds) | `30` |
| `--llm-timeout` | LLM request timeout (seconds) | `120` |
| `--render-wait` | Extra ms to wait after page load (hydration-heavy SPAs) | `0` |
| `-o, --output` | JSON report path (default auto: `~/.piscovery/<target>_<UTC-timestamp>.json`) | auto |
| `--nmap-args` | Extra nmap arguments (shell-quoted) | — |
| `--scan-budget` | Total wall-clock budget seconds (`0`=unlimited) | `1800` |
| `--path-depth-limit` | Reject URLs with more than N path segments | `12` |
| `--query-variants` | Max URLs visited per `(path, query-key-set)` signature | `3` |
| `--no-resource-blocking` | Disable blocking of font/image/media in browser | off |
| `--click-discovery` | Enable active button-click URL discovery (opt-in) | off |
| `--max-clicks` | Max clickable elements explored per page when `--click-discovery` set | `6` |
| `--max-response-bytes` | Drop response bodies larger than N bytes | `5242880` |
| `--max-endpoint-analyses` | Max unique endpoints LLM-analysed individually (`0`=disable) | `20` |
| `--endpoint-body-limit` | Max bytes captured per XHR/fetch response body | `4096` |
| `-v, --verbose` | Show per-URL crawl + LLM progress lines (phase markers always shown) | off |
| `-V, --version` | Print version and exit | — |

## How It Works

### Phase 1: Pre-flight

1. Verify nmap is installed
2. Launch Playwright + system Chrome and probe with `about:blank`
3. Check target is reachable (HTTPS → HTTP fallback)
4. Validate LLM API connectivity

### Phase 2: Parallel Discovery

Runs simultaneously inside a single long-lived Chromium instance:

- **nmap** — Service version detection on all ports (subprocess)
- **Spider** — Recursive web crawl:
  1. Fetch `robots.txt` and `sitemap.xml` (urllib)
  2. For each URL, open a fresh browser **Context** (cookie isolation) and navigate
  3. Inject a History API shim (`pushState`/`replaceState`/`popstate`/`hashchange`) before page scripts run, so SPA route changes are captured passively
  4. Subscribe to `request` events to capture every XHR/fetch call the page makes
  5. Block heavy resources (`font`/`image`/`media`) at the network layer — speeds up + neutralises media tarpits
  6. Read the raw response body via Playwright's `Response` object (server-sent HTML, pre-JS)
  7. Read the post-load DOM via `page.content()` (rendered HTML, post-JS)
  8. Detect SSR vs CSR by comparing the two
  9. Parse rendered HTML — `<a>`, `<area>`, `<link rel="canonical|alternate">`, `[data-href|url|link]`, forms, scripts, meta tags
  10. Walk every iframe (`page.frames`) and parse its DOM the same way
  11. Optionally (with `--click-discovery`) click safe-filtered `<button>` / `[role="button"]` elements and record any URL change — covers React/Vue/Next.js where navigation is bound to `onClick={() => router.push(...)}`
  12. For CSR apps: fetch JS bundles and statically extract client-side routes
  13. Resolve `<link rel="manifest">` PWA manifest, follow its `start_url` / `scope` / `shortcuts[].url`
  14. Follow discovered links up to `--max-depth`

### Phase 3: LLM Analysis (page-level)

Each discovered page is sent to the LLM with:
- URL, title, response headers, cookies
- Form details (fields, methods, actions)
- URL parameters
- Detected technologies
- **Captured XHR/fetch endpoints** (URL, method, post body)
- HTML comments and inline scripts

The LLM returns:
- **Functionality description** — what the page does
- **Attack surfaces** — forms, endpoints, parameters worth testing
- **Vulnerability predictions** — e.g. SQLi on search params, XSS on comment forms, IDOR/auth issues on captured XHR endpoints

### Phase 4: Endpoint Aggregation + LLM Analysis (per-endpoint)

After all pages are crawled, observed traffic is **aggregated into unique endpoints** so that each backend route is judged on its own — not buried in the page that triggered it.

Sources rolled into the endpoint surface:
- Captured XHR / fetch / EventSource requests + responses (status, MIME, body preview, redacted secrets)
- WebSocket sessions (URL, sample frames sent/received, byte-capped, JWT-redacted)
- Form actions (POST/PUT/PATCH/DELETE forms become observed write endpoints — never auto-submitted)
- Static hints from JS bundles (`fetch('/...')`, `axios.{get,post,...}`, `XMLHttpRequest.open(...)`, `new WebSocket(...)`, `new EventSource(...)`, `serviceWorker.register(...)`) and `<link rel="preload"|"prefetch">`

Aggregation:
- Path patterns normalised: `/users/123` → `/users/{id}`, UUIDs → `{uuid}`, long mixed-charset tokens → `{token}` — alphabetic route names preserved (`/v1/version` stays as-is)
- Group key: `(method, normalised_path, query-key-set)`. Identical groups across pages merge. Up to 3 raw URL samples kept per group.
- Best representative sample chosen: non-empty body wins, 4xx/5xx wins over 2xx (more diagnostic value).

Per-endpoint LLM analysis is run on the **top N most interesting** endpoints (`--max-endpoint-analyses`, default 20):
- Score: non-GET method (+3), has request body (+2), 4xx/5xx response (+1), `/api|/auth|/admin|...` path (+2), Set-Cookie/Authorization in response (+1), WebSocket (+1)
- Stratification floor: each non-GET method gets up to 3 slots, WS/SSE up to 2, regardless of score — prevents a GET-heavy site from drowning out the rare DELETE.

The LLM returns per endpoint:
- **Role** — short label like "User registration", "Authentication login", "Search query", "Real-time chat channel"
- **Description** — what the endpoint does
- **Attack points** — concrete suggestions (Mass Assignment / IDOR / SSRF / SQLi / JWT none-alg / etc.) tied to specific fields, headers, or path segments

### Phase 5: Report

Terminal output with colour-coded findings, plus a JSON export saved automatically. Contains both **per-page** and **per-endpoint** sections; pages cross-reference the endpoints they triggered via `triggered_endpoint_keys`.

### Endpoint Discovery is Strictly Dynamic

piscovery does **not** statically probe well-known paths (`/swagger.json`, `/.well-known/openapi`, `/api/`, `/graphql`, etc.). Endpoints come only from:
1. Real browser traffic the application generates (XHR/fetch/WebSocket/EventSource)
2. Site-advertised metadata (robots.txt, sitemap.xml, PWA manifest)
3. JS bundles the site itself shipped (regex extraction of fetch/axios/etc. calls)

302 redirects are followed automatically by Playwright; the crawler operates on the final landed page. POST/PUT/DELETE/PATCH endpoints are captured and analysed but **never replayed** — reconnaissance is non-destructive by contract.

**Default save location:** `~/.piscovery/<sanitised-target>_<UTC-timestamp>.json` plus a sibling `.md` Markdown report at the same stem
- The directory is created on first run
- Target host is sanitised (scheme stripped, unsafe characters replaced with `_`)
- Same-second collisions are resolved by appending `_001`, `_002`, ...
- Override with `-o /custom/path/report.json` (parent directories are auto-created); the Markdown sibling is written next to it as `/custom/path/report.md`
- Both formats carry the same data — JSON for machine post-processing (`jq`, etc.), Markdown for human reading and pasting into engagement reports

**Nmap raw XML sidecar:** when port scanning runs, the original nmap XML is written next to the JSON report as `<basename>.nmap.xml` (e.g. `~/.piscovery/example.com_<ts>.nmap.xml`). The JSON's `nmap.raw_xml_file` field points at it. This file is consumable by external nmap-XML tooling (e.g. `nmap-parse-output`).

## Trap / Infinite-Loading Defence

Recon against deliberately broken targets (badstore-style training apps, calendar bombs, faceted-search combinatorial explosion, redirect loops) needs guards. piscovery layers six:

| # | Defence | Default | Override |
|---|---------|---------|----------|
| 1 | Per-page hard timeout (`asyncio.wait_for` outside Playwright) | `--timeout` + 10 s | tied to `--timeout` |
| 2 | Path depth limit (reject `/a/b/c/.../n`) | 12 segments | `--path-depth-limit` |
| 3 | Query signature dedup — group by `(path, query-key-set)` | 3 variants | `--query-variants` |
| 4 | Whole-scan wall-clock budget | 1800 s | `--scan-budget` (`0`=unlimited) |
| 5 | Heavy resource blocking (font/image/media via `context.route`) | ON | `--no-resource-blocking` |
| 6 | Response body size cap | 5 MiB | `--max-response-bytes` |

`--query-variants 3` means a target with `?id=1, 2, 3, 4, ...` only gets three crawled, not all hundred. Increase if your target legitimately paginates many distinct articles by ID.

## Click Discovery (`--click-discovery`)

**Off by default** — reconnaissance is non-destructive by contract.

When enabled:
- Enumerates `button:visible`, `[role='button']:visible`, `[data-href|url]:visible`, `a:not([href]):visible`
- Skips elements whose visible text or `aria-label` matches a built-in destructive-verb block-list (English + Korean — *delete/remove/buy/pay/checkout/submit/confirm/cancel/save/edit/update/logout/transfer/post/publish*; *삭제/제거/구매/결제/확인/취소/닫기/로그아웃/송금/전송/게시/등록/저장/수정/변경/탈퇴*)
- Skips `[disabled]` elements and `<button type="submit">` inside `<form>`
- Caps clicks per page at `--max-clicks` (default 6)
- After each click, returns to the original URL via fresh `page.goto` (deterministic vs `go_back()`)

This covers React Router / Vue Router / Next.js where navigation is bound to `onClick={() => router.push(...)}` rather than `<a href>`. The History API shim already catches most SPA routing passively, so click discovery is the catch-all for handlers that don't go through `pushState`.

## Output Example

```
  [1] https://target.com/login
  Status: 200  Render: Server-Side Rendered  Title: Login
  Tech: Express, Bootstrap

  Forms:
    Form 1: POST -> /api/auth/login
      - username [text] *
      - password [password] *

  XHR/Fetch Endpoints:
    POST https://target.com/api/auth/login [fetch]
      body: {"username":"...","password":"..."}
    GET https://target.com/api/csrf-token [xhr]

  Functionality:
    User authentication page with username/password login form.
    Performs CSRF-token fetch then sends credentials to /api/auth/login.

  Attack Surfaces:
    1. [Form Input] /api/auth/login
       POST form accepting username and password credentials
       Params: username, password
    2. [API Endpoint] /api/csrf-token
       Token issuance — check rotation, replay, lifetime

  Vulnerability Predictions:
    1. [SQLi] (Medium)
       Location: /api/auth/login username parameter
       Reasoning: Login form sends credentials to API endpoint; if backend
       uses string concatenation for SQL queries, username field is injectable.
       Discovery: Form analysis -> POST to /api/auth/login -> text input
       named 'username' -> common SQLi target in authentication flows.
```

## Folder Structure

```
piscovery/
├── piscovery/
│   ├── __init__.py
│   ├── __main__.py             # CLI entry → core.cli.cli
│   ├── core/
│   │   ├── models.py           # Config, PageInfo, ScanReport, XHREndpoint, ...
│   │   ├── url.py              # normalise_url, is_in_scope, extract_params
│   │   ├── cli.py              # argparse → Config + cli() entry
│   │   ├── preflight.py        # nmap / Chrome / target / LLM checks
│   │   ├── orchestrator.py     # async run() — preflight → spider+nmap → llm → report
│   │   └── report.py           # terminal + JSON output
│   ├── spider/
│   │   ├── chrome.py           # BrowserManager (Playwright + system Chrome)
│   │   ├── render.py           # per-page navigate + XHR capture + DOM extraction
│   │   ├── crawler.py          # BFS scope-aware loop
│   │   ├── sitemap.py          # robots.txt + sitemap.xml (urllib)
│   │   └── parse.py            # HTML parser, tech fingerprinting, CSR routes
│   ├── scanner/
│   │   └── nmap.py             # nmap subprocess + XML parsing
│   └── llm/
│       ├── client.py           # urllib HTTP, OpenAI-compatible
│       └── prompt.py           # prompt building + response parsing
├── tests/
│   ├── core/                   # test_url, test_models
│   ├── spider/                 # test_parse, test_sitemap, test_render
│   ├── scanner/                # test_nmap
│   └── llm/                    # test_prompt
├── pyproject.toml
├── LICENSE
└── README.md
```

## Testing

```bash
python -m pytest tests/ -v
```

The test suite stubs Playwright at the session level, so unit tests run without a real browser. Integration testing requires installed Chrome.

## Licence

MIT

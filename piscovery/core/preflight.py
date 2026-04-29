import ssl
import urllib.error
import urllib.request

from ..llm import check_llm
from ..scanner import is_available as nmap_available
from .models import Config


_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_RESET = "\033[0m"
_BOLD = "\033[1m"

_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


def _ok(msg):
    print(f"  {_GREEN}[OK]{_RESET}  {msg}")


def _fail(msg):
    print(f"  {_RED}[FAIL]{_RESET}  {msg}")


def _warn(msg):
    print(f"  {_YELLOW}[WARN]{_RESET}  {msg}")


def _probe(url: str, timeout: int):
    ctx = ssl.create_default_context()
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return True, f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            if e.code == 405 and method == "HEAD":
                continue
            return True, f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError):
            break
    return False, "unreachable"


def _reachable(target: str, timeout: int = 10):
    if "://" in target:
        ok, status = _probe(target, timeout)
        return (ok, target if ok else "", status)
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        ok, status = _probe(url, timeout)
        if ok:
            return True, url, status
    return False, "", "unreachable"


async def run_preflight(config: Config, chrome_ready: bool = False) -> bool:
    print(f"\n{_BOLD}=== Pre-flight Checks ==={_RESET}\n")
    all_ok = True

    nmap_path = nmap_available()
    if nmap_path:
        _ok(f"nmap found: {nmap_path}")
    elif config.port_scan:
        _fail("nmap not found (required for port scanning)")
        all_ok = False
    else:
        _warn("nmap not found (port scan disabled)")

    if chrome_ready:
        _ok("Playwright + system Chrome ready")
    else:
        _fail("Browser not initialised")
        all_ok = False

    target_ok, target_url, status = _reachable(config.target, config.timeout)
    if target_ok:
        _ok(f"Target reachable: {target_url} ({status})")
        config.target_url = target_url
    else:
        _fail(f"Target unreachable: {config.target}")
        all_ok = False

    if config.llm_api_key:
        llm_ok = await check_llm(config)
        if llm_ok:
            _ok(f"LLM connected: {config.llm_model} @ {config.llm_base_url}")
        else:
            _fail(f"LLM connection failed: {config.llm_base_url}")
            all_ok = False
    else:
        _fail("LLM API key not provided")
        all_ok = False

    print()
    if not all_ok:
        print(f"{_RED}Pre-flight checks failed. Aborting.{_RESET}\n")
        return False

    print(f"{_GREEN}All checks passed. Starting scan...{_RESET}\n")
    return True

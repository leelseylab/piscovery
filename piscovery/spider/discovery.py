import re

from playwright.async_api import (
    Error as PlaywrightError,
    Page,
    TimeoutError as PlaywrightTimeoutError,
)

from ..core.models import Config
from ..core.url import is_in_scope, normalise_url
from .parse import PageHTMLParser


HISTORY_API_SHIM = """
(() => {
    if (window.__piscovery_init) return;
    window.__piscovery_init = true;
    window.__piscovery_urls = [];
    const push = (u) => { try { window.__piscovery_urls.push(String(u)); } catch (e) {} };
    const _ps = history.pushState;
    history.pushState = function (s, t, u) { if (u != null) push(u); return _ps.apply(this, arguments); };
    const _rs = history.replaceState;
    history.replaceState = function (s, t, u) { if (u != null) push(u); return _rs.apply(this, arguments); };
    window.addEventListener("popstate", () => push(location.href));
    window.addEventListener("hashchange", () => push(location.href));
})();
"""


_BLOCK_EN = [
    "delete", "remove", "destroy", "terminate", "ban", "block", "unblock",
    "logout", "log out", "sign out", "signout",
    "buy", "purchase", "pay", "checkout", "order", "subscribe",
    "submit", "confirm", "approve", "reject", "send", "transfer",
    "post", "publish", "save", "update", "edit", "rename",
    "cancel", "close",
]
_BLOCK_KO = [
    "삭제", "제거", "구매", "결제", "확인", "취소", "닫기",
    "로그아웃", "송금", "전송", "게시", "등록", "저장", "수정", "변경",
    "주문", "결제하기", "송금하기", "발송", "발행", "탈퇴",
]


def _build_block_re():
    en = "|".join(re.escape(t) for t in _BLOCK_EN)
    ko = "|".join(re.escape(t) for t in _BLOCK_KO)
    return re.compile(rf"(?<!\w)(?:{en})(?!\w)|{ko}", re.IGNORECASE)


BLOCK_RE = _build_block_re()


def _blocked(text):
    return bool(text) and bool(BLOCK_RE.search(text))


async def history_urls(page: Page, base_url: str) -> list:
    try:
        raw_list = await page.evaluate("() => window.__piscovery_urls || []")
    except PlaywrightError:
        return []

    out, seen = [], set()
    for raw in raw_list:
        if not isinstance(raw, str) or not raw:
            continue
        try:
            full = normalise_url(base_url, raw)
        except Exception:
            continue
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out


async def frame_links(page: Page, base_url: str) -> list:
    out, seen = [], set()
    main = page.main_frame
    for frame in page.frames:
        if frame is main:
            continue
        try:
            html = await frame.content()
        except PlaywrightError:
            continue
        p = PageHTMLParser(frame.url or base_url)
        try:
            p.feed(html)
        except Exception:
            continue
        for link in p.links:
            if link not in seen:
                seen.add(link)
                out.append(link)
    return out


async def _label(loc) -> str:
    parts = []
    try:
        t = await loc.inner_text(timeout=500)
        if t:
            parts.append(t)
    except PlaywrightError:
        pass
    try:
        aria = await loc.get_attribute("aria-label", timeout=500)
        if aria:
            parts.append(aria)
    except PlaywrightError:
        pass
    return " ".join(parts).strip()


async def _safe(loc) -> bool:
    try:
        if await loc.get_attribute("disabled", timeout=300) is not None:
            return False
    except PlaywrightError:
        return False

    text = await _label(loc)
    if not text or _blocked(text):
        return False

    try:
        btn_type = await loc.get_attribute("type", timeout=300)
        tag = await loc.evaluate("el => el.tagName.toLowerCase()", timeout=300)
        in_form = await loc.evaluate("el => !!el.closest('form')", timeout=300)
    except PlaywrightError:
        return False

    if tag == "button" and in_form and (btn_type or "").lower() != "button":
        return False
    return True


_CLICK_SELECTOR = (
    "button:visible, [role='button']:visible, "
    "[data-href]:visible, [data-url]:visible, a:not([href]):visible"
)


async def click_walk(page: Page, config: Config, base_url: str) -> list:
    if not config.click_discovery:
        return []

    try:
        candidates = await page.locator(_CLICK_SELECTOR).all()
    except PlaywrightError:
        return []

    found, seen = [], set()
    walked = 0

    for c in candidates:
        if walked >= config.max_clicks_per_page:
            break
        try:
            ok = await _safe(c)
        except PlaywrightError:
            continue
        if not ok:
            continue

        walked += 1
        before = page.url
        try:
            await c.click(timeout=1500)
        except (PlaywrightError, PlaywrightTimeoutError):
            continue

        try:
            await page.wait_for_timeout(500)
        except PlaywrightError:
            pass

        after = page.url
        if not after or after == before:
            continue

        try:
            url = normalise_url(base_url, after)
        except Exception:
            url = ""
        if url and is_in_scope(url, base_url) and url not in seen:
            seen.add(url)
            found.append(url)

        try:
            await page.goto(before, wait_until="domcontentloaded", timeout=config.timeout * 1000)
        except (PlaywrightError, PlaywrightTimeoutError):
            break

    return found

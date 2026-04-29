import asyncio
import sys
import unittest
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock


def _install_playwright_stub() -> None:
    """Install a minimal playwright.async_api shim so render.py imports."""
    if "playwright" in sys.modules and "playwright.async_api" in sys.modules:
        return
    pkg = ModuleType("playwright")
    api = ModuleType("playwright.async_api")

    class _Err(Exception):
        pass

    class _TimeoutErr(_Err):
        pass

    api.Browser = object
    api.Error = _Err
    api.TimeoutError = _TimeoutErr
    api.Playwright = object
    api.async_playwright = lambda: None
    pkg.async_api = api
    sys.modules["playwright"] = pkg
    sys.modules["playwright.async_api"] = api


_install_playwright_stub()

from piscovery.core import Config  # noqa: E402
from piscovery.spider import render as render_module  # noqa: E402


def _make_config() -> Config:
    cfg = Config(target="example.com")
    cfg.target_url = "https://example.com"
    cfg.timeout = 5
    return cfg


def _build_mock_browser(html: str, headers: dict, status: int = 200, xhr_specs: list | None = None):
    captured: dict = {}

    response = MagicMock()
    response.status = status
    response.all_headers = AsyncMock(return_value=headers)
    response.body = AsyncMock(return_value=html.encode("utf-8"))

    page = MagicMock()
    page.goto = AsyncMock(return_value=response)
    page.content = AsyncMock(return_value=html)
    page.wait_for_load_state = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    page.evaluate = AsyncMock(return_value=[])
    page.url = "https://example.com"
    page.main_frame = MagicMock()
    page.frames = [page.main_frame]
    page.locator = MagicMock(return_value=MagicMock(all=AsyncMock(return_value=[])))

    def on(event, callback):
        captured.setdefault(event, []).append(callback)

    page.on = on

    context = MagicMock()
    context.new_page = AsyncMock(return_value=page)
    context.close = AsyncMock()
    context.cookies = AsyncMock(return_value=[{"name": "session", "value": "abc"}])
    context.add_init_script = AsyncMock()
    context.route = AsyncMock()

    browser = MagicMock()
    browser.new_context = AsyncMock(return_value=context)

    async def fire_xhrs():
        for cb in captured.get("request", []):
            for spec in xhr_specs or []:
                req = MagicMock()
                req.url = spec["url"]
                req.method = spec.get("method", "GET")
                req.resource_type = spec.get("resource_type", "fetch")
                req.post_data = spec.get("post_data", "")
                cb(req)

    return browser, fire_xhrs


class TestRender(unittest.IsolatedAsyncioTestCase):
    async def test_basic_page(self):
        html = "<html><head><title>Hi</title></head><body><a href='/x'>x</a></body></html>"
        browser, fire = _build_mock_browser(html, {"content-type": "text/html"})
        # Patch goto to fire request callbacks before returning
        original_goto = browser.new_context.return_value.new_page.return_value.goto
        async def goto_with_events(*a, **kw):
            await fire()
            return await original_goto(*a, **kw)
        browser.new_context.return_value.new_page.return_value.goto = goto_with_events

        cfg = _make_config()
        page_info = await render_module.render(browser, "https://example.com", cfg, depth=0)

        self.assertIsNotNone(page_info)
        self.assertEqual(page_info.status_code, 200)
        self.assertEqual(page_info.title, "Hi")
        self.assertIn("https://example.com/x", page_info.links)
        self.assertEqual(page_info.cookies, ["session=abc"])

    async def test_xhr_capture(self):
        html = "<html><body>spa</body></html>"
        xhrs = [
            {"url": "https://example.com/api/users", "method": "GET", "resource_type": "fetch"},
            {"url": "https://example.com/api/login", "method": "POST", "resource_type": "xhr", "post_data": "u=x&p=y"},
            {"url": "https://example.com/img.png", "method": "GET", "resource_type": "image"},  # filtered out
        ]
        browser, fire = _build_mock_browser(html, {"content-type": "text/html"}, xhr_specs=xhrs)

        original_goto = browser.new_context.return_value.new_page.return_value.goto
        async def goto_with_events(*a, **kw):
            await fire()
            return await original_goto(*a, **kw)
        browser.new_context.return_value.new_page.return_value.goto = goto_with_events

        cfg = _make_config()
        page_info = await render_module.render(browser, "https://example.com", cfg, depth=0)

        urls = [(ep.method, ep.url) for ep in page_info.xhr_endpoints]
        self.assertIn(("GET", "https://example.com/api/users"), urls)
        self.assertIn(("POST", "https://example.com/api/login"), urls)
        self.assertNotIn(("GET", "https://example.com/img.png"), urls)
        self.assertEqual(len(page_info.xhr_endpoints), 2)
        post_ep = next(ep for ep in page_info.xhr_endpoints if ep.method == "POST")
        self.assertEqual(post_ep.post_data, "u=x&p=y")

    async def test_hard_timeout_returns_none(self):
        async def hang(*a, **kw):
            await asyncio.sleep(10)
            return None

        browser = MagicMock()
        browser.new_context = AsyncMock(side_effect=hang)

        cfg = _make_config()
        cfg.timeout = 0  # hard_timeout = 10 in render() but inner sleeps 10s
        # Use a tiny inner override to hit the wait_for path quickly:
        async def short_render(*a, **kw):
            await asyncio.sleep(0.5)
            return None

        original_inner = render_module._run
        render_module._run = lambda *a, **kw: asyncio.sleep(2)
        try:
            cfg.timeout = -9  # hard_timeout = 1, inner sleeps 2 → TimeoutError
            result = await render_module.render(browser, "https://example.com", cfg, depth=0)
            self.assertIsNone(result)
        finally:
            render_module._run = original_inner

    async def test_resource_blocking_route_registered(self):
        html = "<html><body>x</body></html>"
        browser, _fire = _build_mock_browser(html, {"content-type": "text/html"})
        cfg = _make_config()
        cfg.block_heavy_resources = True
        await render_module.render(browser, "https://example.com", cfg, depth=0)
        ctx = browser.new_context.return_value
        ctx.route.assert_awaited()

    async def test_resource_blocking_skipped_when_disabled(self):
        html = "<html><body>x</body></html>"
        browser, _fire = _build_mock_browser(html, {"content-type": "text/html"})
        cfg = _make_config()
        cfg.block_heavy_resources = False
        await render_module.render(browser, "https://example.com", cfg, depth=0)
        ctx = browser.new_context.return_value
        ctx.route.assert_not_awaited()

    async def test_response_body_size_cap(self):
        big_html = "<html>" + ("a" * 1000) + "</html>"
        browser, _fire = _build_mock_browser(big_html, {"content-type": "text/html"})
        cfg = _make_config()
        cfg.max_response_bytes = 100  # below body size
        page_info = await render_module.render(browser, "https://example.com", cfg, depth=0)
        # raw_html is dropped, but rendered_html (page.content) survives
        self.assertEqual(page_info.raw_html, "")
        self.assertEqual(page_info.rendered_html, big_html)

    async def test_history_urls_merged(self):
        html = "<html><body><a href='/static'>x</a></body></html>"
        browser, _fire = _build_mock_browser(html, {"content-type": "text/html"})
        ctx = browser.new_context.return_value
        page = ctx.new_page.return_value
        page.evaluate = AsyncMock(return_value=["/api/dynamic", "/profile"])

        cfg = _make_config()
        page_info = await render_module.render(browser, "https://example.com", cfg, depth=0)

        self.assertIn("https://example.com/static", page_info.links)
        self.assertIn("https://example.com/api/dynamic", page_info.links)
        self.assertIn("https://example.com/profile", page_info.links)

    async def test_response_capture(self):
        captured: dict = {}

        def on(event, callback):
            captured.setdefault(event, []).append(callback)

        html = "<html><body>x</body></html>"
        browser, _fire = _build_mock_browser(html, {"content-type": "text/html"})
        page = browser.new_context.return_value.new_page.return_value
        page.on = on

        async def fire_response_after_goto(*a, **kw):
            mock_resp = MagicMock()
            mock_resp.url = "https://example.com/api/users"
            mock_resp.status = 200
            mock_resp.request.method = "GET"
            mock_resp.request.resource_type = "fetch"
            mock_resp.all_headers = AsyncMock(return_value={"content-type": "application/json"})
            mock_resp.body = AsyncMock(return_value=b'[{"id": 1, "name": "alice"}]')
            for cb in captured.get("response", []):
                await cb(mock_resp)
            response_obj = MagicMock()
            response_obj.status = 200
            response_obj.all_headers = AsyncMock(return_value={"content-type": "text/html"})
            response_obj.body = AsyncMock(return_value=html.encode("utf-8"))
            return response_obj

        page.goto = fire_response_after_goto

        cfg = _make_config()
        page_info = await render_module.render(browser, "https://example.com", cfg, depth=0)

        self.assertEqual(len(page_info.responses), 1)
        resp = page_info.responses[0]
        self.assertEqual(resp.url, "https://example.com/api/users")
        self.assertEqual(resp.method, "GET")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("alice", resp.body_preview)

    async def test_response_skipped_for_non_xhr_resource(self):
        captured: dict = {}

        def on(event, callback):
            captured.setdefault(event, []).append(callback)

        html = "<html><body>x</body></html>"
        browser, _fire = _build_mock_browser(html, {"content-type": "text/html"})
        page = browser.new_context.return_value.new_page.return_value
        page.on = on

        async def fire_response_after_goto(*a, **kw):
            mock_resp = MagicMock()
            mock_resp.url = "https://example.com/sprite.png"
            mock_resp.status = 200
            mock_resp.request.method = "GET"
            mock_resp.request.resource_type = "image"
            mock_resp.all_headers = AsyncMock(return_value={"content-type": "image/png"})
            for cb in captured.get("response", []):
                await cb(mock_resp)
            response_obj = MagicMock()
            response_obj.status = 200
            response_obj.all_headers = AsyncMock(return_value={"content-type": "text/html"})
            response_obj.body = AsyncMock(return_value=html.encode("utf-8"))
            return response_obj

        page.goto = fire_response_after_goto

        cfg = _make_config()
        page_info = await render_module.render(browser, "https://example.com", cfg, depth=0)

        self.assertEqual(len(page_info.responses), 0)


if __name__ == "__main__":
    unittest.main()

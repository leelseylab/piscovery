import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from piscovery.core import Config
from piscovery.spider.discovery import (
    _blocked,
    frame_links,
    history_urls,
    click_walk,
)


class TestDestructiveDetection(unittest.TestCase):
    def test_english_delete(self):
        self.assertTrue(_blocked("Delete account"))

    def test_english_buy_word_boundary(self):
        self.assertTrue(_blocked("Buy now"))

    def test_english_safe_word(self):
        self.assertFalse(_blocked("View profile"))
        self.assertFalse(_blocked("Read more"))
        self.assertFalse(_blocked("Browse catalogue"))

    def test_korean_delete(self):
        self.assertTrue(_blocked("삭제"))

    def test_korean_logout(self):
        self.assertTrue(_blocked("로그아웃 하기"))

    def test_korean_safe(self):
        self.assertFalse(_blocked("프로필 보기"))
        self.assertFalse(_blocked("더 보기"))

    def test_empty_text(self):
        self.assertFalse(_blocked(""))

    def test_partial_word_not_matched(self):
        # "delete" inside "deleterious" should NOT match because of word boundary
        self.assertFalse(_blocked("deleterious"))

    def test_case_insensitive(self):
        self.assertTrue(_blocked("DELETE"))
        self.assertTrue(_blocked("CheckOut"))

    def test_mixed_text(self):
        self.assertTrue(_blocked("Click here to confirm your order"))


class TestCollectHistoryURLs(unittest.IsolatedAsyncioTestCase):
    async def test_resolves_relative_paths(self):
        page = MagicMock()
        page.evaluate = AsyncMock(return_value=["/dashboard", "/users/123", "https://other.com/x"])
        urls = await history_urls(page, "https://example.com")
        self.assertIn("https://example.com/dashboard", urls)
        self.assertIn("https://example.com/users/123", urls)

    async def test_dedupes(self):
        page = MagicMock()
        page.evaluate = AsyncMock(return_value=["/a", "/a", "/a"])
        urls = await history_urls(page, "https://example.com")
        self.assertEqual(urls, ["https://example.com/a"])

    async def test_handles_evaluate_failure(self):
        from playwright.async_api import Error as PlaywrightError
        page = MagicMock()
        page.evaluate = AsyncMock(side_effect=PlaywrightError("no context"))
        urls = await history_urls(page, "https://example.com")
        self.assertEqual(urls, [])

    async def test_filters_non_strings(self):
        page = MagicMock()
        page.evaluate = AsyncMock(return_value=["/ok", None, 42, "", "/good"])
        urls = await history_urls(page, "https://example.com")
        self.assertEqual(set(urls), {"https://example.com/ok", "https://example.com/good"})


class TestCollectFrameLinks(unittest.IsolatedAsyncioTestCase):
    async def test_iterates_frames_skip_main(self):
        main = MagicMock()
        sub = MagicMock()
        sub.url = "https://example.com/iframe"
        sub.content = AsyncMock(return_value='<a href="/inside">x</a>')

        page = MagicMock()
        page.main_frame = main
        page.frames = [main, sub]

        links = await frame_links(page, "https://example.com")
        self.assertEqual(links, ["https://example.com/inside"])

    async def test_no_subframes(self):
        main = MagicMock()
        page = MagicMock()
        page.main_frame = main
        page.frames = [main]
        links = await frame_links(page, "https://example.com")
        self.assertEqual(links, [])

    async def test_skips_failing_frame(self):
        from playwright.async_api import Error as PlaywrightError
        main = MagicMock()
        bad = MagicMock()
        bad.url = "https://other.com/x"
        bad.content = AsyncMock(side_effect=PlaywrightError("cross-origin"))
        good = MagicMock()
        good.url = "https://example.com/iframe"
        good.content = AsyncMock(return_value='<a href="/found">x</a>')

        page = MagicMock()
        page.main_frame = main
        page.frames = [main, bad, good]

        links = await frame_links(page, "https://example.com")
        self.assertIn("https://example.com/found", links)


class TestDiscoverViaClicks(unittest.IsolatedAsyncioTestCase):
    def _make_config(self, click_discovery: bool = True) -> Config:
        cfg = Config(target="example.com")
        cfg.target_url = "https://example.com"
        cfg.click_discovery = click_discovery
        cfg.max_clicks_per_page = 3
        cfg.timeout = 5
        return cfg

    def _make_locator(self, text: str, *, disabled: bool = False, tag: str = "button", in_form: bool = False, button_type: str = "button"):
        loc = MagicMock()
        loc.get_attribute = AsyncMock(side_effect=lambda name, timeout=None: {
            "disabled": "disabled" if disabled else None,
            "type": button_type,
        }.get(name))
        loc.inner_text = AsyncMock(return_value=text)
        loc.evaluate = AsyncMock(side_effect=lambda script, timeout=None: {
            "el => el.tagName.toLowerCase()": tag,
            "el => !!el.closest('form')": in_form,
        }.get(script))
        loc.click = AsyncMock()
        return loc

    async def test_disabled_skip(self):
        cfg = self._make_config()
        navigated = self._make_locator("Browse")
        disabled = self._make_locator("Browse", disabled=True)

        page = MagicMock()
        page.locator.return_value.all = AsyncMock(return_value=[disabled, navigated])
        page.wait_for_timeout = AsyncMock()
        page.goto = AsyncMock()

        idx = {"i": 0}
        seq = ["https://example.com/", "https://example.com/browse"]
        type(page).url = property(lambda self: seq[min(idx["i"], len(seq) - 1)])

        async def click_advances(**_kw):
            idx["i"] += 1

        navigated.click = AsyncMock(side_effect=click_advances)

        urls = await click_walk(page, cfg, "https://example.com")
        self.assertEqual(urls, ["https://example.com/browse"])
        navigated.click.assert_awaited()

    async def test_destructive_text_skip(self):
        cfg = self._make_config()
        delete_btn = self._make_locator("Delete account")
        page = MagicMock()
        page.url = "https://example.com/"
        page.locator.return_value.all = AsyncMock(return_value=[delete_btn])
        page.wait_for_timeout = AsyncMock()
        page.goto = AsyncMock()
        urls = await click_walk(page, cfg, "https://example.com")
        self.assertEqual(urls, [])
        delete_btn.click.assert_not_awaited()

    async def test_form_submit_skip(self):
        cfg = self._make_config()
        submit = self._make_locator("Go", tag="button", in_form=True, button_type="submit")
        page = MagicMock()
        page.url = "https://example.com/"
        page.locator.return_value.all = AsyncMock(return_value=[submit])
        page.wait_for_timeout = AsyncMock()
        page.goto = AsyncMock()
        urls = await click_walk(page, cfg, "https://example.com")
        self.assertEqual(urls, [])

    async def test_max_clicks_cap(self):
        cfg = self._make_config()
        cfg.max_clicks_per_page = 2
        loc1 = self._make_locator("Page 1")
        loc2 = self._make_locator("Page 2")
        loc3 = self._make_locator("Page 3")

        page = MagicMock()
        page.locator.return_value.all = AsyncMock(return_value=[loc1, loc2, loc3])
        page.wait_for_timeout = AsyncMock()
        page.goto = AsyncMock()
        type(page).url = property(lambda self: "https://example.com/")

        await click_walk(page, cfg, "https://example.com")
        loc1.click.assert_awaited()
        loc2.click.assert_awaited()
        loc3.click.assert_not_awaited()

    async def test_disabled_when_click_discovery_false(self):
        cfg = self._make_config(click_discovery=False)
        page = MagicMock()
        urls = await click_walk(page, cfg, "https://example.com")
        self.assertEqual(urls, [])
        page.locator.assert_not_called()


if __name__ == "__main__":
    unittest.main()

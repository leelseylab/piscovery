from typing import Optional

from playwright.async_api import Browser, Playwright, async_playwright


_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--mute-audio",
]


class BrowserManager:
    def __init__(self, channel: str = "chrome", headless: bool = True):
        self.channel = channel
        self.headless = headless
        self._pw: Optional[Playwright] = None
        self.browser: Optional[Browser] = None

    async def __aenter__(self) -> "BrowserManager":
        self._pw = await async_playwright().start()
        self.browser = await self._pw.chromium.launch(
            channel=self.channel,
            headless=self.headless,
            args=_LAUNCH_ARGS,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            if self.browser is not None:
                await self.browser.close()
        finally:
            if self._pw is not None:
                await self._pw.stop()
            self.browser = None
            self._pw = None

    async def close(self) -> None:
        await self.__aexit__(None, None, None)


async def probe() -> tuple[bool, str]:
    """Best-effort verification that Playwright + system Chrome are usable."""
    try:
        async with BrowserManager() as bm:
            assert bm.browser is not None
            ctx = await bm.browser.new_context()
            page = await ctx.new_page()
            await page.goto("about:blank", timeout=5000)
            await ctx.close()
        return True, "ok"
    except Exception as e:
        return False, str(e).splitlines()[0] if str(e) else type(e).__name__

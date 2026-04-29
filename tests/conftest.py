import sys
from types import ModuleType


def _install_playwright_stub() -> None:
    if "playwright.async_api" in sys.modules:
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
    api.Page = object
    api.Frame = object
    api.Locator = object
    api.Request = object
    api.Response = object
    api.Route = object
    api.Playwright = object
    api.async_playwright = lambda: None
    pkg.async_api = api
    sys.modules["playwright"] = pkg
    sys.modules["playwright.async_api"] = api


_install_playwright_stub()

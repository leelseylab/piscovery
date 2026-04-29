import asyncio
import unittest
from unittest.mock import patch

from piscovery.core import Config
from piscovery.spider import sitemap


def _make_config() -> Config:
    cfg = Config(target="example.com")
    cfg.target_url = "https://example.com"
    return cfg


class TestRobots(unittest.TestCase):
    def test_parses_disallow_and_sitemap(self):
        body = (
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /private/\n"
            "Sitemap: https://example.com/sitemap.xml\n"
            "Sitemap: https://example.com/news-sitemap.xml\n"
        )

        async def fake_fetch_url(url, config):
            return 200, {}, {}, body

        with patch.object(sitemap, "fetch_url", fake_fetch_url):
            disallowed, sitemaps = asyncio.run(sitemap.fetch_robots(_make_config()))

        self.assertEqual(disallowed, ["/admin", "/private/"])
        self.assertEqual(
            sitemaps,
            ["https://example.com/sitemap.xml", "https://example.com/news-sitemap.xml"],
        )

    def test_404_returns_empty(self):
        async def fake_fetch_url(url, config):
            return 404, {}, {}, ""

        with patch.object(sitemap, "fetch_url", fake_fetch_url):
            disallowed, sitemaps = asyncio.run(sitemap.fetch_robots(_make_config()))
        self.assertEqual(disallowed, [])
        self.assertEqual(sitemaps, [])


class TestSitemap(unittest.TestCase):
    def test_extracts_locs(self):
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset><url><loc>https://example.com/a</loc></url>'
            '<url><loc>https://example.com/b</loc></url></urlset>'
        )

        async def fake_fetch_url(url, config):
            return 200, {}, {}, xml

        with patch.object(sitemap, "fetch_url", fake_fetch_url):
            urls = asyncio.run(sitemap.fetch_sitemap(_make_config()))

        self.assertIn("https://example.com/a", urls)
        self.assertIn("https://example.com/b", urls)

    def test_nested_sitemap(self):
        index = (
            '<sitemapindex>'
            '<sitemap><loc>https://example.com/sub.xml</loc></sitemap>'
            '</sitemapindex>'
        )
        sub = (
            '<urlset><url><loc>https://example.com/inner</loc></url></urlset>'
        )

        async def fake_fetch_url(url, config):
            if url.endswith("/sub.xml"):
                return 200, {}, {}, sub
            return 200, {}, {}, index

        with patch.object(sitemap, "fetch_url", fake_fetch_url):
            urls = asyncio.run(
                sitemap.fetch_sitemap(_make_config(), ["https://example.com/sitemap.xml"])
            )

        self.assertIn("https://example.com/inner", urls)


if __name__ == "__main__":
    unittest.main()

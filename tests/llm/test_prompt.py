import unittest

from piscovery.core import PageInfo, XHREndpoint
from piscovery.llm.prompt import (
    _build_body_excerpt,
    _build_page_summary,
    _extract_html_comments,
    _extract_inline_scripts,
    _parse_analysis,
)


class TestBodyExcerpt(unittest.TestCase):
    def test_extracts_comments(self):
        html = "<html><!-- TODO: remove debug --><!-- secret key --><body>hi</body></html>"
        comments = _extract_html_comments(html)
        self.assertEqual(len(comments), 2)
        self.assertIn(" TODO: remove debug ", comments)

    def test_extracts_inline_scripts(self):
        html = '<script>var API_KEY="sk-123";</script><script src="/app.js"></script><script>init();</script>'
        scripts = _extract_inline_scripts(html)
        self.assertEqual(len(scripts), 2)
        self.assertIn('var API_KEY="sk-123";', scripts)

    def test_build_body_includes_comments_and_scripts(self):
        page = PageInfo(
            url="https://example.com",
            raw_html='<html><!-- admin panel at /debug --><script>var token="abc";</script><body>content</body></html>',
        )
        excerpt = _build_body_excerpt(page)
        self.assertIn("admin panel", excerpt)
        self.assertIn('var token="abc"', excerpt)

    def test_empty_body(self):
        page = PageInfo(url="https://example.com")
        excerpt = _build_body_excerpt(page)
        self.assertIn("empty body", excerpt)


class TestPageSummary(unittest.TestCase):
    def test_includes_request_headers(self):
        page = PageInfo(
            url="https://example.com/login",
            status_code=200,
            request_headers={"Host": "example.com", "User-Agent": "Test"},
            response_headers={"server": "nginx", "set-cookie": "sid=abc; HttpOnly"},
        )
        summary = _build_page_summary(page)
        self.assertIn("HTTP REQUEST", summary)
        self.assertIn("Host: example.com", summary)
        self.assertIn("HTTP RESPONSE", summary)
        self.assertIn("server: nginx", summary)
        self.assertIn("set-cookie: sid=abc; HttpOnly", summary)

    def test_includes_url_path_and_query(self):
        page = PageInfo(
            url="https://example.com/search?q=test&page=1",
            status_code=200,
            parameters={"q": "test", "page": "1"},
        )
        summary = _build_page_summary(page)
        self.assertIn("GET /search?q=test&page=1", summary)

    def test_includes_xhr_endpoints(self):
        page = PageInfo(
            url="https://example.com/dashboard",
            status_code=200,
            xhr_endpoints=[
                XHREndpoint(url="https://example.com/api/users", method="GET", resource_type="fetch"),
                XHREndpoint(url="https://example.com/api/login", method="POST", resource_type="xhr", post_data="u=x"),
                XHREndpoint(url="https://example.com/api/users", method="GET", resource_type="fetch"),  # duplicate
            ],
        )
        summary = _build_page_summary(page)
        self.assertIn("XHR/Fetch Endpoints", summary)
        self.assertIn("GET https://example.com/api/users", summary)
        self.assertIn("POST https://example.com/api/login", summary)
        self.assertIn("body: u=x", summary)
        # duplicates collapsed: header should say 2 unique
        self.assertIn("(2 unique)", summary)


class TestLLMParsing(unittest.TestCase):
    def test_parse_valid_json(self):
        raw = '{"category": "Login Page", "description": "Auth form", "suggestions": []}'
        result = _parse_analysis(raw)
        self.assertEqual(result.category, "Login Page")
        self.assertEqual(result.description, "Auth form")

    def test_parse_fenced_json(self):
        raw = '```json\n{"category": "Dashboard", "description": "Admin panel", "suggestions": []}\n```'
        result = _parse_analysis(raw)
        self.assertEqual(result.category, "Dashboard")

    def test_parse_invalid_json(self):
        raw = "This is not JSON"
        result = _parse_analysis(raw)
        self.assertEqual(result.description, raw)

    def test_parse_full_response(self):
        raw = '''{
            "category": "Bulletin Board",
            "description": "Displays user posts",
            "suggestions": [
                {
                    "attack_type": "Stored XSS",
                    "target": "Post body textarea",
                    "reasoning": "User content rendered as HTML",
                    "observation": "textarea name=content in POST form"
                },
                {
                    "attack_type": "SQLi",
                    "target": "?page= parameter",
                    "reasoning": "Numeric param likely in SQL WHERE",
                    "observation": "GET /board?page=1"
                }
            ]
        }'''
        result = _parse_analysis(raw)
        self.assertEqual(result.category, "Bulletin Board")
        self.assertEqual(len(result.suggestions), 2)
        self.assertEqual(result.suggestions[0].attack_type, "Stored XSS")
        self.assertEqual(result.suggestions[1].target, "?page= parameter")


if __name__ == "__main__":
    unittest.main()

import unittest

from piscovery.core import EndpointInfo
from piscovery.llm.endpoint_prompt import (
    _summary,
    _parse,
)


class TestBuildEndpointSummary(unittest.TestCase):
    def test_includes_method_and_url(self):
        ep = EndpointInfo(url="/api/users/{id}", method="GET")
        summary = _summary(ep)
        self.assertIn("GET /api/users/{id}", summary)

    def test_includes_request_body(self):
        ep = EndpointInfo(url="/api/login", method="POST", post_data='{"u":"x","p":"y"}')
        summary = _summary(ep)
        self.assertIn("REQUEST", summary)
        self.assertIn('"u":"x"', summary)

    def test_includes_response_data(self):
        ep = EndpointInfo(
            url="/api/items",
            method="GET",
            status_code=200,
            response_mime="application/json",
            response_body_preview='[{"id":1}]',
            response_headers={"set-cookie": "s=1; HttpOnly"},
        )
        summary = _summary(ep)
        self.assertIn("HTTP 200", summary)
        self.assertIn("application/json", summary)
        self.assertIn('[{"id":1}]', summary)
        self.assertIn("set-cookie", summary)

    def test_includes_observed_pages(self):
        ep = EndpointInfo(
            url="/api/orders",
            method="POST",
            observed_on_pages=["https://x/checkout", "https://x/cart"],
        )
        summary = _summary(ep)
        self.assertIn("Observed on pages", summary)
        self.assertIn("https://x/checkout", summary)


class TestParseEndpointAnalysis(unittest.TestCase):
    def test_valid_json(self):
        raw = '{"role":"User Login","description":"Auth endpoint","suggestions":[]}'
        a = _parse(raw)
        self.assertEqual(a.role, "User Login")
        self.assertEqual(a.description, "Auth endpoint")

    def test_fenced_json(self):
        raw = '```json\n{"role":"Search","description":"x","suggestions":[]}\n```'
        a = _parse(raw)
        self.assertEqual(a.role, "Search")

    def test_with_suggestions(self):
        raw = """{
            "role": "Order Create",
            "description": "Creates an order",
            "suggestions": [
                {"attack_type": "Mass Assignment", "target": "is_admin field", "reasoning": "POST JSON unfiltered", "observation": "post_data has user fields"}
            ]
        }"""
        a = _parse(raw)
        self.assertEqual(len(a.suggestions), 1)
        self.assertEqual(a.suggestions[0].attack_type, "Mass Assignment")

    def test_invalid_json_falls_back(self):
        raw = "not json"
        a = _parse(raw)
        self.assertEqual(a.description, raw)
        self.assertEqual(a.role, "")


if __name__ == "__main__":
    unittest.main()

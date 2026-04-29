import unittest

from piscovery.core import EndpointInfo
from piscovery.spider.endpoints import (
    group,
    path_pattern,
    score,
    pick_top,
)


class TestNormalisePathPattern(unittest.TestCase):
    def test_numeric_id(self):
        self.assertEqual(
            path_pattern("https://x/users/123"),
            "https://x/users/{id}",
        )

    def test_uuid(self):
        self.assertEqual(
            path_pattern("https://x/users/550e8400-e29b-41d4-a716-446655440000"),
            "https://x/users/{uuid}",
        )

    def test_token_alphanumeric(self):
        self.assertEqual(
            path_pattern("https://x/share/abcDEF123_xyz789"),
            "https://x/share/{token}",
        )

    def test_alphabetic_route_preserved(self):
        # /v1/version must NOT collapse to /v1/{id}
        self.assertEqual(
            path_pattern("https://x/v1/version"),
            "https://x/v1/version",
        )

    def test_short_string_preserved(self):
        # 'me' and other short alpha names stay
        self.assertEqual(
            path_pattern("https://x/users/me"),
            "https://x/users/me",
        )

    def test_query_keys_preserved_values_dropped(self):
        result = path_pattern("https://x/search?q=hello&page=1")
        self.assertEqual(result, "https://x/search?page=&q=")

    def test_mixed_segments(self):
        self.assertEqual(
            path_pattern("https://x/api/users/42/orders/abcd1234efgh5678"),
            "https://x/api/users/{id}/orders/{token}",
        )

    def test_short_id_word_not_collapsed(self):
        # "id" itself is alphabetic — keep
        self.assertEqual(
            path_pattern("https://x/api/id"),
            "https://x/api/id",
        )


class TestScoreEndpoint(unittest.TestCase):
    def test_get_plain(self):
        ep = EndpointInfo(url="https://x/static.txt", method="GET")
        self.assertEqual(score(ep), 0.0)

    def test_post_with_body(self):
        ep = EndpointInfo(url="https://x/api/login", method="POST", post_data='{"u":"x"}')
        # +3 (POST) + 2 (post_data) + 2 (path /api...)
        self.assertEqual(score(ep), 7.0)

    def test_4xx_response(self):
        ep = EndpointInfo(url="https://x/admin", method="GET", status_code=403)
        # +1 (4xx) + 2 (path /admin)
        self.assertEqual(score(ep), 3.0)

    def test_set_cookie_header(self):
        ep = EndpointInfo(url="https://x/auth", method="POST", response_headers={"Set-Cookie": "s=1"})
        # +3 (POST) + 2 (path /auth) + 1 (set-cookie)
        self.assertEqual(score(ep), 6.0)

    def test_websocket_bonus(self):
        ep = EndpointInfo(url="wss://x/ws", method="WS", resource_type="websocket")
        # +1 (websocket)
        self.assertEqual(score(ep), 1.0)


class TestGroupEndpoints(unittest.TestCase):
    def test_dedup_by_pattern(self):
        obs = [
            {"method": "GET", "url": "https://x/users/1", "page_url": "https://x/p1"},
            {"method": "GET", "url": "https://x/users/2", "page_url": "https://x/p1"},
            {"method": "GET", "url": "https://x/users/999", "page_url": "https://x/p2"},
        ]
        groups = group(obs)
        self.assertEqual(len(groups), 1)
        ep = groups[0]
        self.assertEqual(ep.url, "https://x/users/{id}")
        self.assertEqual(ep.sample_count, 3)
        self.assertEqual(len(ep.raw_url_samples), 3)
        self.assertEqual(len(ep.observed_on_pages), 2)

    def test_method_distinguishes(self):
        obs = [
            {"method": "GET", "url": "https://x/api"},
            {"method": "POST", "url": "https://x/api"},
        ]
        groups = group(obs)
        self.assertEqual(len(groups), 2)

    def test_4xx_sample_wins(self):
        obs = [
            {"method": "GET", "url": "https://x/p", "status_code": 200, "response_body_preview": "ok"},
            {"method": "GET", "url": "https://x/p", "status_code": 403, "response_body_preview": "denied"},
        ]
        groups = group(obs)
        self.assertEqual(groups[0].status_code, 403)
        self.assertEqual(groups[0].response_body_preview, "denied")

    def test_non_empty_body_wins(self):
        obs = [
            {"method": "GET", "url": "https://x/p", "status_code": 200, "response_body_preview": ""},
            {"method": "GET", "url": "https://x/p", "status_code": 200, "response_body_preview": "{...}"},
        ]
        groups = group(obs)
        self.assertEqual(groups[0].response_body_preview, "{...}")


class TestSelectTopEndpoints(unittest.TestCase):
    def _ep(self, method, url, score):
        ep = EndpointInfo(url=url, method=method)
        ep.interest_score = score
        return ep

    def test_zero_limit_returns_empty(self):
        eps = [self._ep("GET", "https://x/a", 5)]
        self.assertEqual(pick_top(eps, 0), [])

    def test_top_n_by_score(self):
        eps = [
            self._ep("GET", "https://x/a", 1),
            self._ep("GET", "https://x/b", 5),
            self._ep("GET", "https://x/c", 3),
        ]
        result = pick_top(eps, 2)
        urls = [e.url for e in result]
        self.assertIn("https://x/b", urls)
        self.assertIn("https://x/c", urls)

    def test_stratification_floor_includes_delete(self):
        # Many high-score GETs, one low-score DELETE — DELETE must be selected
        eps = [self._ep("GET", f"https://x/a{i}", 10) for i in range(20)]
        eps.append(self._ep("DELETE", "https://x/api/users/me", 0.1))
        result = pick_top(eps, 5)
        methods = [e.method for e in result]
        self.assertIn("DELETE", methods)

    def test_capacity_respected(self):
        eps = [self._ep("GET", f"https://x/p{i}", float(i)) for i in range(10)]
        result = pick_top(eps, 3)
        self.assertEqual(len(result), 3)


if __name__ == "__main__":
    unittest.main()

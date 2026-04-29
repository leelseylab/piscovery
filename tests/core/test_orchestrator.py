import unittest

from piscovery.core import (
    FormField,
    FormInfo,
    PageInfo,
    ResponseObservation,
    WebSocketObservation,
    XHREndpoint,
)
from piscovery.core.orchestrator import _obs, _keys


def _make_page_with_traffic() -> PageInfo:
    return PageInfo(
        url="https://example.com/dashboard",
        xhr_endpoints=[
            XHREndpoint(url="https://example.com/api/users/42", method="GET", resource_type="fetch", post_data=""),
            XHREndpoint(url="https://example.com/api/login", method="POST", resource_type="xhr", post_data='{"u":"x"}'),
        ],
        responses=[
            ResponseObservation(
                url="https://example.com/api/users/42",
                method="GET",
                status_code=200,
                headers={"content-type": "application/json"},
                mime="application/json",
                body_preview='{"id":42,"name":"alice"}',
            ),
            ResponseObservation(
                url="https://example.com/api/standalone",
                method="GET",
                status_code=204,
                headers={},
                mime="application/json",
                body_preview="",
            ),
        ],
        ws_observations=[
            WebSocketObservation(
                url="wss://example.com/socket",
                sent_preview='{"action":"subscribe"}',
                received_preview='{"event":"hello"}',
            ),
        ],
        forms=[
            FormInfo(
                action="https://example.com/api/profile",
                method="POST",
                fields=[
                    FormField(name="username", field_type="text", required=True),
                    FormField(name="email", field_type="email", required=True),
                ],
            ),
            FormInfo(
                action="https://example.com/search",
                method="GET",
                fields=[FormField(name="q", field_type="text")],
            ),
        ],
        static_endpoint_hints=[
            {"method": "GET", "url": "/api/feature-flags", "resource_type": "js-static"},
        ],
    )


class TestObservationsFromPage(unittest.TestCase):
    def setUp(self):
        self.page = _make_page_with_traffic()
        self.obs = _obs(self.page)

    def test_xhr_joined_with_response(self):
        users_obs = next(o for o in self.obs if o["url"] == "https://example.com/api/users/42")
        self.assertEqual(users_obs["status_code"], 200)
        self.assertIn("alice", users_obs["response_body_preview"])

    def test_xhr_without_response_present(self):
        login_obs = next(o for o in self.obs if o["url"] == "https://example.com/api/login")
        self.assertEqual(login_obs["method"], "POST")
        self.assertEqual(login_obs["post_data"], '{"u":"x"}')
        self.assertEqual(login_obs["status_code"], 0)

    def test_response_without_xhr_added(self):
        # A response observed without a matching XHR (e.g. fetch fired before listener)
        obs_urls = {o["url"] for o in self.obs}
        self.assertIn("https://example.com/api/standalone", obs_urls)

    def test_websocket_observation(self):
        ws = next(o for o in self.obs if o["resource_type"] == "websocket")
        self.assertEqual(ws["method"], "WS")
        self.assertEqual(ws["url"], "wss://example.com/socket")
        self.assertIn("subscribe", ws["post_data"])
        self.assertIn("hello", ws["response_body_preview"])

    def test_post_form_promoted(self):
        form_obs = next(
            o for o in self.obs
            if o["url"] == "https://example.com/api/profile" and o["resource_type"] == "form-post"
        )
        self.assertEqual(form_obs["method"], "POST")
        self.assertIn("username", form_obs["post_data"])

    def test_get_form_promoted(self):
        form_obs = next(
            o for o in self.obs
            if o["url"] == "https://example.com/search" and o["resource_type"] == "form-get"
        )
        self.assertEqual(form_obs["method"], "GET")
        self.assertEqual(form_obs["post_data"], "")

    def test_static_hint_carried_through(self):
        hint = next(o for o in self.obs if o["url"] == "/api/feature-flags")
        self.assertEqual(hint["resource_type"], "js-static")

    def test_page_url_attached(self):
        for o in self.obs:
            self.assertEqual(o["page_url"], "https://example.com/dashboard")


class TestTriggeredKeys(unittest.TestCase):
    def test_dedup_by_pattern(self):
        page = _make_page_with_traffic()
        obs = _obs(page)
        keys = _keys(obs)
        # /api/users/42 normalised to /api/users/{id}
        self.assertIn("GET https://example.com/api/users/{id}", keys)
        # POST and GET are distinct keys for same form action
        # Methods preserved
        methods = {k.split(" ", 1)[0] for k in keys}
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)
        self.assertIn("WS", methods)


if __name__ == "__main__":
    unittest.main()

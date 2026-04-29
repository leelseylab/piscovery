import unittest

from piscovery.core import RenderType
from piscovery.spider.parse import (
    PageHTMLParser,
    detect_render_type,
    detect_technologies,
    extract_endpoints,
    extract_routes,
    extract_sw,
    is_html,
    parse_cookies,
)


class TestHTMLParser(unittest.TestCase):
    def test_parse_links(self):
        html = '<html><body><a href="/about">About</a><a href="/contact">Contact</a></body></html>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertEqual(len(parser.links), 2)
        self.assertIn("https://example.com/about", parser.links)

    def test_dedup_links(self):
        html = '<a href="/a">A</a><a href="/a">A</a><a href="/a">A</a>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertEqual(len(parser.links), 1)

    def test_skip_data_href(self):
        html = '<a href="data:text/html,hello">x</a><a href="/ok">y</a>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertEqual(len(parser.links), 1)
        self.assertIn("https://example.com/ok", parser.links)

    def test_parse_forms(self):
        html = '''<html><body>
        <form action="/login" method="POST">
          <input name="user" type="text" required>
          <input name="pass" type="password">
        </form></body></html>'''
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertEqual(len(parser.forms), 1)
        self.assertEqual(parser.forms[0].method, "POST")
        self.assertEqual(len(parser.forms[0].fields), 2)
        self.assertTrue(parser.forms[0].fields[0].required)

    def test_parse_title(self):
        html = "<html><head><title>Test Page</title></head></html>"
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertEqual(parser.title, "Test Page")

    def test_parse_scripts(self):
        html = '<html><body><script src="/js/app.js"></script></body></html>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertEqual(len(parser.scripts), 1)
        self.assertIn("app.js", parser.scripts[0])

    def test_link_canonical(self):
        html = '<head><link rel="canonical" href="/canonical-page"></head>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertIn("https://example.com/canonical-page", parser.links)

    def test_link_alternate(self):
        html = '<head><link rel="alternate" hreflang="ko" href="/ko/home"></head>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertIn("https://example.com/ko/home", parser.links)

    def test_link_manifest(self):
        html = '<head><link rel="manifest" href="/app.webmanifest"></head>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertEqual(parser.manifest_url, "https://example.com/app.webmanifest")
        self.assertNotIn("https://example.com/app.webmanifest", parser.links)

    def test_link_stylesheet_ignored(self):
        html = '<head><link rel="stylesheet" href="/style.css"></head>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertNotIn("https://example.com/style.css", parser.links)

    def test_area_href(self):
        html = '<map><area shape="rect" coords="0,0,10,10" href="/map-target"></map>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertIn("https://example.com/map-target", parser.links)

    def test_data_href_attribute(self):
        html = '<button data-href="/profile">Profile</button><div data-url="/dashboard"></div>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertIn("https://example.com/profile", parser.links)
        self.assertIn("https://example.com/dashboard", parser.links)

    def test_data_link_attribute(self):
        html = '<span data-link="/settings">Settings</span>'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertIn("https://example.com/settings", parser.links)


class TestRenderType(unittest.TestCase):
    def test_csr_with_framework_and_content_growth(self):
        raw = '<html><div id="root" data-reactroot></div></html>'
        rendered = '<html><div id="root" data-reactroot><nav>Menu</nav><main>Lots of content here for testing</main></div></html>'
        self.assertEqual(detect_render_type(raw, rendered), RenderType.CSR)

    def test_ssr_with_framework_no_growth(self):
        raw = '<html><div data-reactroot><nav>Menu</nav><main>Content already here</main></div></html>'
        rendered = '<html><div data-reactroot><nav>Menu</nav><main>Content already here</main></div></html>'
        self.assertEqual(detect_render_type(raw, rendered), RenderType.SSR)

    def test_static_minimal(self):
        raw = "<html><body>Hi</body></html>"
        rendered = "<html><body>Hi</body></html>"
        self.assertEqual(detect_render_type(raw, rendered), RenderType.STATIC)

    def test_unknown_no_rendered(self):
        self.assertEqual(detect_render_type("<html></html>", ""), RenderType.UNKNOWN)


class TestCookieParsing(unittest.TestCase):
    def test_simple_cookie(self):
        headers = {"set-cookie": "session=abc123; Path=/; HttpOnly"}
        self.assertEqual(parse_cookies(headers), ["session=abc123"])

    def test_no_cookies(self):
        self.assertEqual(parse_cookies({}), [])

    def test_multiple_cookies(self):
        headers = {"set-cookie": "a=1; Path=/, b=2; Path=/"}
        self.assertEqual(len(parse_cookies(headers)), 2)


class TestContentTypeCheck(unittest.TestCase):
    def test_html(self):
        self.assertTrue(is_html({"content-type": "text/html; charset=utf-8"}))

    def test_json(self):
        self.assertFalse(is_html({"content-type": "application/json"}))

    def test_image(self):
        self.assertFalse(is_html({"content-type": "image/png"}))

    def test_empty(self):
        self.assertTrue(is_html({}))


class TestTechDetection(unittest.TestCase):
    def test_detect_wordpress(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/test/style.css">'
        self.assertIn("WordPress", detect_technologies(html, {}))

    def test_detect_react(self):
        html = '<div id="root" data-reactroot></div>'
        self.assertIn("React", detect_technologies(html, {}))

    def test_detect_from_headers(self):
        self.assertIn("Express", detect_technologies("", {"x-powered-by": "Express"}))


class TestRouteExtraction(unittest.TestCase):
    def test_react_routes(self):
        js = '''
        const routes = [
          { path: '/dashboard', component: Dashboard },
          { path: '/users', component: Users },
          { path: '/settings', component: Settings },
        ];
        '''
        routes = extract_routes(js)
        self.assertIn("/dashboard", routes)
        self.assertIn("/users", routes)
        self.assertIn("/settings", routes)

    def test_jsx_routes(self):
        js = '''
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        '''
        routes = extract_routes(js)
        self.assertIn("/login", routes)
        self.assertIn("/register", routes)


class TestEndpointExtraction(unittest.TestCase):
    def test_fetch_default_get(self):
        eps = extract_endpoints("fetch('/api/users')")
        self.assertEqual(eps[0]["method"], "GET")
        self.assertEqual(eps[0]["url"], "/api/users")

    def test_fetch_with_post_method(self):
        js = "fetch('/api/login', { method: 'POST', body: JSON.stringify(x) })"
        eps = extract_endpoints(js)
        self.assertEqual(eps[0]["method"], "POST")
        self.assertEqual(eps[0]["url"], "/api/login")

    def test_axios_methods(self):
        js = """
        axios.get('/api/items')
        axios.post('/api/order', payload)
        axios.delete('/api/items/' + id)
        """
        eps = extract_endpoints(js)
        methods = sorted([e["method"] for e in eps])
        self.assertEqual(methods, ["DELETE", "GET", "POST"])

    def test_axios_object_form(self):
        js = """axios({ method: 'PUT', url: '/api/profile', data: x })"""
        eps = extract_endpoints(js)
        self.assertEqual(eps[0]["method"], "PUT")
        self.assertEqual(eps[0]["url"], "/api/profile")

    def test_jquery_post(self):
        js = "$.post('/legacy/save', { id: 1 })"
        eps = extract_endpoints(js)
        self.assertEqual(eps[0]["method"], "POST")

    def test_xmlhttprequest_open(self):
        js = "var x = new XMLHttpRequest(); x.open('PATCH', '/api/notes/5');"
        eps = extract_endpoints(js)
        self.assertEqual(eps[0]["method"], "PATCH")
        self.assertEqual(eps[0]["url"], "/api/notes/5")

    def test_websocket_constructor(self):
        js = """const ws = new WebSocket('wss://chat.example.com/socket');"""
        eps = extract_endpoints(js)
        self.assertEqual(eps[0]["resource_type"], "websocket")
        self.assertEqual(eps[0]["method"], "WS")

    def test_eventsource_constructor(self):
        js = """const es = new EventSource('/api/stream');"""
        eps = extract_endpoints(js)
        self.assertEqual(eps[0]["resource_type"], "eventsource")
        self.assertEqual(eps[0]["url"], "/api/stream")

    def test_dedup(self):
        js = "fetch('/a'); fetch('/a'); fetch('/a');"
        eps = extract_endpoints(js)
        self.assertEqual(len(eps), 1)


class TestSwRegistration(unittest.TestCase):
    def test_register_match(self):
        js = "navigator.serviceWorker.register('/sw.js')"
        self.assertEqual(extract_sw(js), ["/sw.js"])

    def test_no_match(self):
        self.assertEqual(extract_sw("plain code"), [])


class TestPreloadHints(unittest.TestCase):
    def test_link_preload(self):
        html = '<link rel="preload" as="fetch" href="/api/init" />'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertIn("https://example.com/api/init", parser.preload_hints)

    def test_link_prefetch(self):
        html = '<link rel="prefetch" href="/next-page-data.json" />'
        parser = PageHTMLParser("https://example.com")
        parser.feed(html)
        self.assertIn("https://example.com/next-page-data.json", parser.preload_hints)


if __name__ == "__main__":
    unittest.main()

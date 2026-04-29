import unittest

from piscovery.core import extract_params, is_in_scope, normalise_url, strip_target_scheme


class TestNormaliseURL(unittest.TestCase):
    def test_basic_join(self):
        self.assertEqual(normalise_url("https://example.com/page", "/about"), "https://example.com/about")

    def test_trailing_slash_removed(self):
        self.assertEqual(normalise_url("https://example.com", "/path/"), "https://example.com/path")

    def test_preserves_query(self):
        self.assertEqual(normalise_url("https://example.com", "/search?q=test"), "https://example.com/search?q=test")

    def test_relative_path(self):
        self.assertEqual(normalise_url("https://example.com/a/b", "c"), "https://example.com/a/c")

    def test_root_path(self):
        self.assertEqual(normalise_url("https://example.com/a/b", "/"), "https://example.com/")

    def test_strips_fragment(self):
        self.assertEqual(normalise_url("https://example.com", "/page#section"), "https://example.com/page")


class TestStripTargetScheme(unittest.TestCase):
    def test_https(self):
        self.assertEqual(strip_target_scheme("https://example.com"), "example.com")

    def test_with_port(self):
        self.assertEqual(strip_target_scheme("https://example.com:8443"), "example.com:8443")

    def test_no_scheme(self):
        self.assertEqual(strip_target_scheme("192.168.1.1"), "192.168.1.1")

    def test_http_with_path(self):
        self.assertEqual(strip_target_scheme("http://10.0.0.1:8080"), "10.0.0.1:8080")


class TestIsInScope(unittest.TestCase):
    def test_same_host(self):
        self.assertTrue(is_in_scope("https://example.com/page", "https://example.com"))

    def test_different_host(self):
        self.assertFalse(is_in_scope("https://other.com/page", "https://example.com"))

    def test_non_http(self):
        self.assertFalse(is_in_scope("ftp://example.com/file", "https://example.com"))

    def test_different_port(self):
        self.assertFalse(is_in_scope("https://example.com:8080/", "https://example.com"))


class TestExtractParams(unittest.TestCase):
    def test_no_params(self):
        self.assertEqual(extract_params("https://example.com/page"), {})

    def test_single_param(self):
        self.assertEqual(extract_params("https://example.com/search?q=test"), {"q": "test"})

    def test_multiple_params(self):
        self.assertEqual(extract_params("https://example.com/page?a=1&b=2"), {"a": "1", "b": "2"})

    def test_empty_value(self):
        self.assertEqual(extract_params("https://example.com/page?flag"), {"flag": ""})


if __name__ == "__main__":
    unittest.main()

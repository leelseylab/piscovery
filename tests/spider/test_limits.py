import unittest

from piscovery.spider.limits import SignatureCounter, is_path_too_deep, signature_key


class TestPathDepth(unittest.TestCase):
    def test_shallow_path(self):
        self.assertFalse(is_path_too_deep("https://x/a/b", 5))

    def test_at_limit(self):
        self.assertFalse(is_path_too_deep("https://x/a/b/c/d/e", 5))

    def test_over_limit(self):
        self.assertTrue(is_path_too_deep("https://x/a/b/c/d/e/f", 5))

    def test_root(self):
        self.assertFalse(is_path_too_deep("https://x/", 5))

    def test_zero_limit_disabled(self):
        self.assertFalse(is_path_too_deep("https://x/a/b/c/d/e/f/g/h/i/j/k", 0))

    def test_trailing_slash_segments_ignored(self):
        self.assertFalse(is_path_too_deep("https://x/a/b/c/", 3))


class TestSignatureKey(unittest.TestCase):
    def test_no_query(self):
        self.assertEqual(signature_key("https://x/p"), ("/p", frozenset()))

    def test_query_keys_extracted(self):
        path, keys = signature_key("https://x/search?q=hi&page=1")
        self.assertEqual(path, "/search")
        self.assertEqual(keys, frozenset({"q", "page"}))

    def test_value_independence(self):
        a = signature_key("https://x/p?id=1")
        b = signature_key("https://x/p?id=999")
        self.assertEqual(a, b)

    def test_param_order_independence(self):
        a = signature_key("https://x/p?a=1&b=2")
        b = signature_key("https://x/p?b=2&a=1")
        self.assertEqual(a, b)

    def test_empty_query_string(self):
        a = signature_key("https://x/p")
        b = signature_key("https://x/p?")
        self.assertEqual(a, b)


class TestSignatureCounter(unittest.TestCase):
    def test_under_limit(self):
        c = SignatureCounter(3)
        self.assertFalse(c.see("https://x/p?id=1"))
        self.assertFalse(c.see("https://x/p?id=2"))
        self.assertFalse(c.see("https://x/p?id=3"))

    def test_over_limit(self):
        c = SignatureCounter(2)
        c.see("https://x/p?id=1")
        c.see("https://x/p?id=2")
        self.assertTrue(c.see("https://x/p?id=3"))

    def test_distinct_signatures_isolated(self):
        c = SignatureCounter(1)
        self.assertFalse(c.see("https://x/a?id=1"))
        self.assertFalse(c.see("https://x/b?id=1"))
        self.assertTrue(c.see("https://x/a?id=2"))

    def test_zero_limit_disabled(self):
        c = SignatureCounter(0)
        for i in range(100):
            self.assertFalse(c.see(f"https://x/p?id={i}"))

    def test_param_order_collapses(self):
        c = SignatureCounter(2)
        c.see("https://x/p?a=1&b=2")
        c.see("https://x/p?b=4&a=3")
        self.assertTrue(c.see("https://x/p?a=5&b=6"))


if __name__ == "__main__":
    unittest.main()

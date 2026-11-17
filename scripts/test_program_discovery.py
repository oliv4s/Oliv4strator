"""Offline route extraction from one response; no target requests."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import program_discovery
import program_policy


class ProgramDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, _ = program_policy.load(ROOT, "demo-program")

    def test_html_links_are_candidates_and_queries_are_redacted(self):
        html = '''<html><head><title>Shop</title><script src="/assets/app.js"></script></head>
        <body><a href="/checkout?token=secret123&step=1">Cart</a>
        <a href="https://api.example.test/v1/items">API</a>
        <a href="https://blog.example.test/post">Blog</a>
        <a href="javascript:alert(1)">Ignored</a></body></html>'''
        found = program_discovery.extract(self.policy, "https://shop.example.test/", html, "text/html")
        self.assertEqual(found["format"], "html")
        self.assertEqual(found["title"], "Shop")
        by_url = {row["url"]: row for row in found["candidates"]}
        checkout = by_url["https://shop.example.test/checkout"]
        self.assertEqual(checkout["query_keys"], ["step", "token"])
        self.assertEqual(checkout["scope_decision"], "review")
        self.assertEqual(by_url["https://api.example.test/v1/items"]["scope_decision"], "allow")
        self.assertEqual(by_url["https://blog.example.test/post"]["scope_decision"], "deny")
        self.assertNotIn("secret123", str(found))

    def test_robots_sitemap_and_javascript(self):
        robots = program_discovery.extract(self.policy, "https://shop.example.test/robots.txt",
                                           "User-agent: *\nDisallow: /checkout\nSitemap: https://shop.example.test/sitemap.xml\n")
        self.assertEqual(robots["format"], "robots")
        self.assertEqual(robots["candidate_count"], 2)
        sitemap = program_discovery.extract(self.policy, "https://shop.example.test/sitemap.xml",
                                            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                                            '<url><loc>https://shop.example.test/product/a</loc></url></urlset>',
                                            "application/xml")
        self.assertEqual(sitemap["candidates"][0]["url"], "https://shop.example.test/product/a")
        js = program_discovery.extract(self.policy, "https://shop.example.test/app.js",
                                       'const api="/api/products"; const cdn="https://cdn.example.test/a";',
                                       "application/javascript")
        self.assertEqual(js["format"], "javascript")
        self.assertEqual(js["candidates"][0]["url"], "https://shop.example.test/api/products")

    def test_javascript_routes_beyond_fixed_api_words(self):
        js = program_discovery.extract(
            self.policy, "https://api.example.test/assets/app.js",
            'fetch("/dashboard/reports?id=secret123"); const asset="/assets/logo.png"; '
            'const next=`/settings/profile`; const external="https://outside.example.test/x";',
            "application/javascript")
        urls = {row["url"] for row in js["candidates"]}
        self.assertIn("https://api.example.test/dashboard/reports", urls)
        self.assertIn("https://api.example.test/settings/profile", urls)
        self.assertNotIn("https://api.example.test/assets/logo.png", urls)
        self.assertNotIn("secret123", str(js))


if __name__ == "__main__":
    unittest.main()

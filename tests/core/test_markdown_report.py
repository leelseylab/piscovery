import tempfile
import unittest
from pathlib import Path

from piscovery.core import (
    AttackSuggestion,
    EndpointAnalysis,
    EndpointInfo,
    EndpointReport,
    LLMAnalysis,
    NmapResult,
    PageInfo,
    PageReport,
    RenderType,
    ScanReport,
    XHREndpoint,
)
from piscovery.core.report import save_markdown_report


def _build_sample_report() -> ScanReport:
    page = PageInfo(
        url="https://example.com/login",
        depth=0,
        status_code=200,
        title="Login",
        render_type=RenderType.SSR,
        technologies=["nginx", "Express"],
        xhr_endpoints=[
            XHREndpoint(url="https://example.com/api/auth", method="POST",
                        resource_type="fetch", post_data='{"u":"x"}'),
        ],
        response_headers={"server": "nginx", "set-cookie": "s=1; HttpOnly"},
    )
    page_analysis = LLMAnalysis(
        category="Login Page",
        description="User authentication form.",
        suggestions=[
            AttackSuggestion(
                attack_type="SQLi",
                target="username param",
                reasoning="String concat suspected",
                observation="POST form to /api/auth",
            ),
        ],
    )
    page_report = PageReport(
        page=page,
        analysis=page_analysis,
        triggered_endpoint_keys=["POST https://example.com/api/auth"],
    )

    endpoint = EndpointInfo(
        url="https://example.com/api/auth",
        raw_url_samples=["https://example.com/api/auth"],
        method="POST",
        resource_type="fetch",
        post_data='{"u":"x"}',
        status_code=200,
        response_mime="application/json",
        response_body_preview='{"token":"abc"}',
        observed_on_pages=["https://example.com/login"],
        sample_count=2,
        interest_score=7.0,
    )
    endpoint_analysis = EndpointAnalysis(
        role="User Login",
        description="Returns auth token.",
        suggestions=[
            AttackSuggestion(
                attack_type="JWT none-alg",
                target="Authorization header on subsequent requests",
                reasoning="Token issuance endpoint",
                observation="Sets cookie + body has token",
            ),
        ],
    )
    endpoint_report = EndpointReport(endpoint=endpoint, analysis=endpoint_analysis)

    return ScanReport(
        target="example.com",
        target_url="https://example.com",
        render_type=RenderType.SSR,
        technologies=["nginx", "Express"],
        nmap=NmapResult(
            open_ports=["80/tcp", "443/tcp"],
            services={"80/tcp": "http (nginx)", "443/tcp": "https (nginx)"},
            os_detection="Linux 5.x",
        ),
        sitemap_urls=["https://example.com/about"],
        robots_info={"disallowed": ["/admin"], "sitemaps": ["https://example.com/sitemap.xml"]},
        pages=[page_report],
        endpoints=[endpoint_report],
    )


class TestSaveMarkdownReport(unittest.TestCase):
    def setUp(self):
        self.report = _build_sample_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scan.md"
        save_markdown_report(self.report, str(self.path))
        self.body = self.path.read_text(encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_file_created(self):
        self.assertTrue(self.path.exists())

    def test_top_header(self):
        self.assertIn("# piscovery Scan Report — example.com", self.body)

    def test_target_metadata(self):
        self.assertIn("**Target:** `example.com`", self.body)
        self.assertIn("**Target URL:** https://example.com", self.body)

    def test_port_scan_table(self):
        self.assertIn("## Port Scan", self.body)
        self.assertIn("`80/tcp`", self.body)
        self.assertIn("http (nginx)", self.body)

    def test_technologies_listed(self):
        self.assertIn("## Technologies", self.body)
        self.assertIn("`nginx`", self.body)
        self.assertIn("`Express`", self.body)

    def test_robots_disallowed(self):
        self.assertIn("### Disallowed paths", self.body)
        self.assertIn("`/admin`", self.body)

    def test_pages_section(self):
        self.assertIn("## Pages", self.body)
        self.assertIn("Login Page", self.body)
        self.assertIn("User authentication form.", self.body)

    def test_page_attack_suggestion(self):
        self.assertIn("**SQLi**", self.body)
        self.assertIn("username param", self.body)

    def test_endpoints_section(self):
        self.assertIn("## Endpoints (1 unique)", self.body)
        self.assertIn("### POST (1)", self.body)
        self.assertIn("User Login", self.body)
        self.assertIn("Returns auth token.", self.body)

    def test_endpoint_attack_points(self):
        self.assertIn("JWT none-alg", self.body)

    def test_summary_section(self):
        self.assertIn("## Summary", self.body)
        self.assertIn("Pages discovered: **1**", self.body)
        self.assertIn("Unique endpoints: **1**", self.body)


class TestEmptyReport(unittest.TestCase):
    def test_minimal_report_writes(self):
        report = ScanReport(target="x", target_url="https://x")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.md"
            save_markdown_report(report, str(path))
            body = path.read_text()
        self.assertIn("# piscovery Scan Report — x", body)
        self.assertIn("## Summary", body)


if __name__ == "__main__":
    unittest.main()

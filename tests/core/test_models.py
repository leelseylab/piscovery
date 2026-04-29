import json
import re
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from piscovery.core import (
    Config,
    NmapResult,
    PageInfo,
    PageReport,
    RenderType,
    ScanReport,
    XHREndpoint,
)
from piscovery.core.report import default_output_path, save_report


class TestModelDefaults(unittest.TestCase):
    def test_pageinfo_xhr_endpoints_default_empty(self):
        page = PageInfo(url="https://example.com")
        self.assertEqual(page.xhr_endpoints, [])

    def test_xhr_endpoint_defaults(self):
        ep = XHREndpoint()
        self.assertEqual(ep.url, "")
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.resource_type, "")
        self.assertEqual(ep.post_data, "")

    def test_config_render_wait_default(self):
        cfg = Config(target="x")
        self.assertEqual(cfg.render_wait, 0)

    def test_scanreport_render_type_default(self):
        report = ScanReport()
        self.assertEqual(report.render_type, RenderType.UNKNOWN)


class TestSerialisation(unittest.TestCase):
    def test_xhr_endpoint_round_trip(self):
        ep = XHREndpoint(
            url="https://api.example.com/v1/users",
            method="POST",
            resource_type="fetch",
            post_data='{"name":"x"}',
        )
        d = asdict(ep)
        self.assertEqual(json.loads(json.dumps(d)), d)

    def test_pagereport_with_analysis_none(self):
        pr = PageReport(page=PageInfo(url="x"))
        self.assertIsNone(pr.analysis)


class TestDefaultOutputPath(unittest.TestCase):
    def test_path_under_piscovery_dir(self):
        with patch("piscovery.core.report._OUTPUT_DIR", Path("/tmp/_piscovery_test_dir")):
            path = default_output_path("https://example.com")
        self.assertEqual(path.parent, Path("/tmp/_piscovery_test_dir"))
        self.assertTrue(path.name.endswith(".json"))

    def test_target_sanitised(self):
        with patch("piscovery.core.report._OUTPUT_DIR", Path("/tmp/_piscovery_test_dir")):
            path = default_output_path("https://example.com:8443/admin?x=1")
        self.assertNotIn("/", path.name)
        self.assertNotIn("?", path.name)
        self.assertNotIn(":", path.name.replace(":", ""))
        self.assertTrue(path.name.startswith("example.com_8443"))

    def test_timestamp_in_filename(self):
        with patch("piscovery.core.report._OUTPUT_DIR", Path("/tmp/_piscovery_test_dir")):
            path = default_output_path("target.local")
        self.assertRegex(path.name, r"target\.local_\d{8}T\d{6}Z\.json")

    def test_collision_appends_counter(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            with patch("piscovery.core.report._OUTPUT_DIR", tmp_dir):
                first = default_output_path("dup")
                first.write_text("{}")
                second = default_output_path("dup")
        self.assertNotEqual(first, second)
        self.assertRegex(second.name, r"dup_\d{8}T\d{6}Z_001\.json")


class TestCLIValidation(unittest.TestCase):
    def _run_cli(self, *flags):
        from piscovery.core.cli import parse_args
        import sys
        old = sys.argv
        sys.argv = ["piscovery", "x", "--api-key", "k", *flags]
        try:
            return parse_args()
        finally:
            sys.argv = old

    def test_negative_scan_budget_rejected(self):
        with self.assertRaises(SystemExit):
            self._run_cli("--scan-budget", "-1")

    def test_negative_path_depth_rejected(self):
        with self.assertRaises(SystemExit):
            self._run_cli("--path-depth-limit", "-5")

    def test_zero_values_accepted(self):
        cfg = self._run_cli("--scan-budget", "0", "--query-variants", "0")
        self.assertEqual(cfg.scan_budget, 0)
        self.assertEqual(cfg.query_variants_limit, 0)

    def test_verbose_default_false(self):
        cfg = self._run_cli()
        self.assertFalse(cfg.verbose)

    def test_verbose_short_flag(self):
        cfg = self._run_cli("-v")
        self.assertTrue(cfg.verbose)

    def test_verbose_long_flag(self):
        cfg = self._run_cli("--verbose")
        self.assertTrue(cfg.verbose)

    def test_capital_v_is_version(self):
        # -V should print version + exit
        with self.assertRaises(SystemExit):
            self._run_cli("-V")


class TestNmapXmlSidecar(unittest.TestCase):
    def test_raw_xml_written_to_sibling_file(self):
        import tempfile
        nmap = NmapResult(
            raw_output="<?xml version='1.0'?><nmaprun><host/></nmaprun>",
            open_ports=["80/tcp"],
            services={"80/tcp": "http"},
        )
        report = ScanReport(target="x", target_url="http://x", nmap=nmap)

        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "scan.json"
            save_report(report, str(json_path))

            xml_path = json_path.with_suffix(".nmap.xml")
            self.assertTrue(xml_path.exists())
            self.assertIn("nmaprun", xml_path.read_text())

            data = json.loads(json_path.read_text())
            self.assertEqual(data["nmap"]["raw_xml_file"], str(xml_path))

    def test_no_xml_when_nmap_skipped(self):
        import tempfile
        report = ScanReport(target="x", target_url="http://x", nmap=None)
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "scan.json"
            save_report(report, str(json_path))

            xml_path = json_path.with_suffix(".nmap.xml")
            self.assertFalse(xml_path.exists())

            data = json.loads(json_path.read_text())
            self.assertNotIn("nmap", data)

    def test_no_xml_on_timeout_sentinel(self):
        import tempfile
        nmap = NmapResult(raw_output="[nmap timed out]")
        report = ScanReport(target="x", target_url="http://x", nmap=nmap)
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "scan.json"
            save_report(report, str(json_path))

            xml_path = json_path.with_suffix(".nmap.xml")
            self.assertFalse(xml_path.exists())

            data = json.loads(json_path.read_text())
            self.assertNotIn("raw_xml_file", data["nmap"])


if __name__ == "__main__":
    unittest.main()

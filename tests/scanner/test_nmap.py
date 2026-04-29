import shlex
import unittest

from piscovery.core import NmapResult
from piscovery.scanner.nmap import _parse_xml


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <osmatch name="Linux 5.x"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapXMLParse(unittest.TestCase):
    def test_open_ports_extracted(self):
        result = NmapResult()
        _parse_xml(SAMPLE_XML, result)
        self.assertEqual(sorted(result.open_ports), ["443/tcp", "80/tcp"])

    def test_closed_port_skipped(self):
        result = NmapResult()
        _parse_xml(SAMPLE_XML, result)
        self.assertNotIn("22/tcp", result.open_ports)

    def test_service_with_version(self):
        result = NmapResult()
        _parse_xml(SAMPLE_XML, result)
        self.assertEqual(result.services["80/tcp"], "http (nginx 1.25.0)")

    def test_service_without_version(self):
        result = NmapResult()
        _parse_xml(SAMPLE_XML, result)
        self.assertEqual(result.services["443/tcp"], "https (nginx)")

    def test_os_detection(self):
        result = NmapResult()
        _parse_xml(SAMPLE_XML, result)
        self.assertEqual(result.os_detection, "Linux 5.x")

    def test_invalid_xml_does_not_raise(self):
        result = NmapResult()
        _parse_xml("not xml at all", result)
        self.assertEqual(result.open_ports, [])


class TestArgSplitting(unittest.TestCase):
    def test_quoted_args_preserved(self):
        # legacy split() would have broken these; shlex preserves quoting.
        self.assertEqual(shlex.split("-p '1-100'"), ["-p", "1-100"])

    def test_multiple_flags(self):
        self.assertEqual(shlex.split("-sC -sV --top-ports 1000"), ["-sC", "-sV", "--top-ports", "1000"])


if __name__ == "__main__":
    unittest.main()

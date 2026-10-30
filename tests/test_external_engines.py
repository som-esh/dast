"""External engine adapters: ZAP, Nuclei, Burp (AR-3).

Parser tests run against captured tool output (pure, no tool installed).
Integration tests inject a canned subprocess runner so the real adapter
code path executes end-to-end and findings flow into the unified schema.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from asvp.engine.adapters import BurpAdapter, NucleiAdapter, ZapAdapter
from asvp.engine.adapters.base import normalize_severity
from asvp.models.scan import ScanRequest
from tests.conftest import DEMO_COLLECTION, make_platform, tier1_service

ZAP_REPORT = """
{"site":[{"@name":"http://payments.staging.svc","alerts":[
  {"pluginid":"40012","alert":"Cross Site Scripting (Reflected)",
   "riskdesc":"High (Medium)","desc":"<p>XSS</p>","solution":"<p>Encode output</p>",
   "cweid":"79","instances":[{"uri":"http://payments.staging.svc/accounts","method":"GET","param":"q","evidence":"<script>"}]},
  {"pluginid":"10038","alert":"Missing CSP","riskdesc":"Low (Medium)","desc":"no csp","solution":"add csp",
   "instances":[{"uri":"http://payments.staging.svc/","method":"GET"}]}
]}]}
"""

NUCLEI_JSONL = (
    '{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info"},'
    '"matched-at":"http://payments.staging.svc/","type":"http"}\n'
    '{"template-id":"exposed-env","info":{"name":"Exposed .env","severity":"high",'
    '"description":"env exposed","remediation":"remove it",'
    '"classification":{"cwe-id":["cwe-200"]}},"matched-at":"http://payments.staging.svc/.env"}\n'
    "\n"  # blank line tolerated
)

BURP_XML = """<?xml version="1.0"?>
<issues>
  <issue>
    <serialNumber>123</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="10.0.0.1">http://payments.staging.svc</host>
    <path>/transfers</path>
    <location>/transfers [amount parameter]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>&lt;p&gt;SQLi background&lt;/p&gt;</issueBackground>
    <remediationBackground>&lt;p&gt;Use params&lt;/p&gt;</remediationBackground>
  </issue>
</issues>
"""


class TestSeverityNormalization(unittest.TestCase):
    def test_maps_vocabularies(self):
        self.assertEqual(normalize_severity("High (Medium)"), "high")
        self.assertEqual(normalize_severity("Informational"), "info")
        self.assertEqual(normalize_severity("critical"), "critical")
        self.assertEqual(normalize_severity("Information"), "info")
        self.assertEqual(normalize_severity(""), "info")


class TestParsers(unittest.TestCase):
    def test_zap_report_parses(self):
        findings = ZapAdapter.parse_report(ZAP_REPORT)
        self.assertEqual(len(findings), 2)
        xss = findings[0]
        self.assertEqual(xss.engine, "zap")
        self.assertEqual(xss.severity, "high")
        self.assertEqual(xss.endpoint_id, "GET /accounts")
        self.assertEqual(xss.parameter, "q")
        self.assertNotIn("<p>", xss.description)  # HTML stripped
        self.assertEqual(xss.check_id, "zap:40012")

    def test_nuclei_jsonl_parses(self):
        findings = NucleiAdapter.parse_jsonl(NUCLEI_JSONL)
        self.assertEqual(len(findings), 2)
        env = [f for f in findings if f.rule_id == "exposed-env"][0]
        self.assertEqual(env.severity, "high")
        self.assertEqual(env.endpoint_id, "GET /.env")
        self.assertIn("CWE-200", env.compliance_mappings)

    def test_burp_xml_parses(self):
        findings = BurpAdapter.parse_report(BURP_XML)
        self.assertEqual(len(findings), 1)
        sqli = findings[0]
        self.assertEqual(sqli.engine, "burp")
        self.assertEqual(sqli.severity, "high")
        self.assertEqual(sqli.endpoint_id, "GET /transfers")
        self.assertEqual(sqli.parameter, "amount")
        self.assertNotIn("<p>", sqli.description)

    def test_parsers_tolerate_garbage(self):
        self.assertEqual(ZapAdapter.parse_report("not json"), [])
        self.assertEqual(NucleiAdapter.parse_jsonl("not\njson\nlines"), [])
        self.assertEqual(BurpAdapter.parse_report("<broken"), [])


class TestAvailability(unittest.TestCase):
    def test_unconfigured_engines_unavailable(self):
        self.assertFalse(ZapAdapter(path="").is_available())
        self.assertFalse(NucleiAdapter(path="").is_available())
        self.assertFalse(BurpAdapter(jar_path="").is_available())

    def test_configured_path_is_available(self):
        with tempfile.NamedTemporaryFile(suffix=".jar", delete=False) as fh:
            jar = fh.name
        try:
            # java resolves on PATH in CI; if not, availability is False and
            # the engine is simply skipped — both are valid, so assert the
            # jar-existence half deterministically via the binary engines.
            self.assertTrue(ZapAdapter(path=jar).is_available())
            self.assertTrue(NucleiAdapter(path=jar).is_available())
        finally:
            os.unlink(jar)


class TestExternalEngineIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Dummy binaries so is_available() is true; canned runners return
        # captured tool output, exercising the real parse + ingest path.
        self._tmp = tempfile.TemporaryDirectory()
        zap_bin = os.path.join(self._tmp.name, "zap")
        nuclei_bin = os.path.join(self._tmp.name, "nuclei")
        for b in (zap_bin, nuclei_bin):
            open(b, "w").close()

        async def zap_runner(cmd, cwd=None, timeout=None):
            return (0, ZAP_REPORT, "")

        async def nuclei_runner(cmd, cwd=None, timeout=None):
            return (0, NUCLEI_JSONL, "")

        engines = {
            "zap": ZapAdapter(path=zap_bin, runner=zap_runner),
            "nuclei": NucleiAdapter(path=nuclei_bin, runner=nuclei_runner),
        }
        from tests.conftest import vulnerable_client_factory
        from asvp.integrations.secrets import InMemorySecretsManager

        self.platform = make_platform()
        # rebuild platform with injected engine registry
        self.platform = type(self.platform)(
            db_path=":memory:",
            secrets=InMemorySecretsManager(
                {"secret:payments/alice": "tok-alice", "secret:payments/bob": "tok-bob"}
            ),
            client_factory=vulnerable_client_factory,
            target_rps=1000.0,
            external_engines=engines,
        )
        await self.platform.orchestrator.start(runner_count=4)
        svc = tier1_service()
        svc.external_engines = ["zap", "nuclei", "burp"]  # burp unconfigured → skipped
        self.platform.registry.register(svc)
        self.platform.ingest_spec(DEMO_COLLECTION, "payments-api")

    async def asyncTearDown(self):
        await self.platform.close()
        self._tmp.cleanup()

    async def test_external_findings_flow_into_unified_schema(self):
        req = ScanRequest(service="payments-api", spec_version="latest",
                          environment="staging", profile="preprod", mode="full")
        status = await self.platform.orchestrator.submit(req)
        status = await self.platform.orchestrator.wait(status.scan_id, timeout=60)

        self.assertIn("zap", status.engines_run)
        self.assertIn("nuclei", status.engines_run)
        self.assertTrue(any("burp" in s for s in status.engines_skipped))
        self.assertGreater(status.external_findings_count, 0)

        findings = self.platform.findings.all("payments-api")
        engines = {f.check_id.split(":")[0] for f in findings if ":" in f.check_id}
        self.assertIn("zap", engines)
        self.assertIn("nuclei", engines)
        # external findings participate in the gate (a ZAP High blocks pre-prod)
        self.assertEqual(status.gate_verdict["verdict"], "block")

    async def test_safe_mode_skips_aggressive_engines(self):
        req = ScanRequest(service="payments-api", spec_version="latest",
                          environment="staging", profile="qa", mode="safe")
        status = await self.platform.orchestrator.submit(req)
        status = await self.platform.orchestrator.wait(status.scan_id, timeout=60)
        self.assertEqual(status.engines_run, [])
        self.assertTrue(any("zap" in s for s in status.engines_skipped))


if __name__ == "__main__":
    unittest.main()

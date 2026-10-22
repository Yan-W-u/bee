"""SARIF 与 baseline 的测试。

这两个模块的产出会直接被外部工具消费（GitHub Code Scanning、PR 评论），
格式错一个字段就整条链路失效，所以要卡结构。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from bee import baseline, sarif
from bee.models import Finding, Severity, TraceStep


def make_finding(**kwargs) -> Finding:
    base = dict(
        rule_id="bee.sql-injection",
        severity=Severity.ERROR,
        message="SQL 注入（字符串拼接构造查询）",
        path="app.py",
        start_line=10,
        end_line=11,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        snippet='sql = "SELECT " + k',
        code_line='sql = "SELECT " + k',
        raw={"root_cause_hint": "外部数据进了 SQL 文本", "fix_hint": "改成参数化"},
    )
    base.update(kwargs)
    return Finding(**base)


class TestSarif(unittest.TestCase):
    def test_structure(self):
        doc = sarif.to_sarif([make_finding()], tool_version="9.9.9")
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        self.assertEqual(len(doc["runs"]), 1)

        run = doc["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "bee")
        self.assertEqual(driver["version"], "9.9.9")
        self.assertEqual(len(driver["rules"]), 1)
        self.assertEqual(len(run["results"]), 1)
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_severity_mapping(self):
        cases = {
            Severity.ERROR: "error",
            Severity.WARNING: "warning",
            Severity.INFO: "note",
        }
        for sev, level in cases.items():
            doc = sarif.to_sarif([make_finding(severity=sev)])
            self.assertEqual(doc["runs"][0]["results"][0]["level"], level)

    def test_security_severity_present(self):
        """GitHub 用 security-severity 排优先级，缺了所有问题权重都一样。"""
        doc = sarif.to_sarif([make_finding()])
        props = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        self.assertIn("security-severity", props)
        self.assertGreaterEqual(float(props["security-severity"]), 0.0)
        self.assertLessEqual(float(props["security-severity"]), 10.0)

    def test_rce_class_scores_higher_than_info(self):
        high = sarif.to_sarif([make_finding(cwe=["CWE-94"])])
        low = sarif.to_sarif([make_finding(severity=Severity.INFO, cwe=["CWE-489"])])
        h = float(high["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"])
        l = float(low["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"])
        self.assertGreater(h, l)

    def test_uri_is_relative_and_fingerprint_present(self):
        doc = sarif.to_sarif([make_finding(path="src/app.py")])
        result = doc["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertEqual(loc["uri"], "src/app.py")
        self.assertEqual(loc["uriBaseId"], "%SRCROOT%")
        self.assertIn("beeFingerprint/v1", result["partialFingerprints"])

    def test_rule_deduplicated(self):
        findings = [make_finding(start_line=10), make_finding(start_line=20)]
        doc = sarif.to_sarif(findings)
        self.assertEqual(len(doc["runs"][0]["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(doc["runs"][0]["results"]), 2)

    def test_code_flows_from_trace(self):
        finding = make_finding(trace=[
            TraceStep("source", "app.py", 3, "k = request.args['k']"),
            TraceStep("sink", "app.py", 10, "execute(sql)"),
        ])
        doc = sarif.to_sarif([finding])
        result = doc["runs"][0]["results"][0]
        self.assertIn("codeFlows", result)
        flow = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(flow), 2)

    def test_write_creates_valid_json(self):
        tmp = Path(tempfile.mkdtemp(prefix="bee-sarif-"))
        try:
            out = sarif.write([make_finding()], tmp / "sub" / "bee.sarif")
            self.assertTrue(out.exists())
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], "2.1.0")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-baseline-"))
        self.path = self.tmp / "base.json"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_roundtrip(self):
        findings = [make_finding(start_line=10), make_finding(rule_id="bee.xss", path="b.js")]
        baseline.save(baseline.build(findings), self.path)
        loaded = baseline.load(self.path)
        self.assertEqual(loaded.size, 2)
        self.assertEqual(loaded.tool, "bee")

    def test_split_identifies_new(self):
        known = make_finding(start_line=10)
        base = baseline.build([known])
        fresh = make_finding(start_line=99, rule_id="bee.ssrf", code_line="requests.get(u)")
        new, already = baseline.split([known, fresh], base)
        self.assertEqual(len(new), 1)
        self.assertEqual(len(already), 1)
        self.assertEqual(new[0].rule_id, "bee.ssrf")

    def test_fingerprint_stable_when_line_moves(self):
        """行号变化不能让已有问题变成「新增」——这是基线可用的前提。"""
        a = make_finding(start_line=10)
        b = make_finding(start_line=42)
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_fingerprint_changes_when_code_changes(self):
        a = make_finding(code_line='sql = "SELECT " + k')
        b = make_finding(code_line='sql = "SELECT ?", (k,)')
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_empty_baseline_treats_all_as_new(self):
        new, already = baseline.split([make_finding()], baseline.Baseline())
        self.assertEqual(len(new), 1)
        self.assertEqual(already, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

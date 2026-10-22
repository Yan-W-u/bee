"""semgrep 后端转换的测试。

本机装不上 semgrep（Windows 需要 WSL/Docker），所以这里用官方输出的
真实 JSON 结构做离线转换测试。转换层正确才是可验证的部分——
探测和调用只能用集成测试补。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from bee import semgrep_backend
from bee.models import Severity


SAMPLE_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query",
            "path": "app/db.py",
            "start": {"line": 12, "col": 5},
            "end": {"line": 13, "col": 20},
            "extra": {
                "message": "Detected possible formatted SQL query.",
                "severity": "ERROR",
                "lines": 'sql = f"SELECT * FROM t WHERE id = {uid}"',
                "metadata": {
                    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                    "owasp": ["A03:2021 - Injection"],
                    "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
                    "confidence": "HIGH",
                    "shortDescription": "formatted sql query",
                },
                "dataflow_trace": {
                    "taint_source": [
                        "CliLoc",
                        [
                            {
                                "path": "app/api.py",
                                "start": {"line": 5},
                                "end": {"line": 5},
                                "content": "uid = request.args['id']",
                            }
                        ],
                    ],
                    "intermediate_vars": [
                        {
                            "location": {"path": "app/db.py", "start": {"line": 10}},
                            "content": "query = build(uid)",
                        }
                    ],
                    "taint_sink": [
                        "CliLoc",
                        [
                            {
                                "path": "app/db.py",
                                "start": {"line": 12},
                                "end": {"line": 13},
                                "content": "cursor.execute(sql)",
                            }
                        ],
                    ],
                },
            },
        }
    ],
    "errors": [],
}


class TestConversion(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-semgrep-"))
        (self.tmp / "app").mkdir(parents=True, exist_ok=True)
        (self.tmp / "app" / "db.py").write_text("x = 1\n", encoding="utf-8", newline="")
        (self.tmp / "app" / "api.py").write_text("y = 2\n", encoding="utf-8", newline="")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_converts_single_result(self):
        finding = semgrep_backend._to_finding(SAMPLE_JSON["results"][0], self.tmp)
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.rule_id, "python.lang.security.audit.formatted-sql-query")
        self.assertEqual(finding.severity, Severity.ERROR)
        self.assertEqual(finding.path, "app/db.py")
        self.assertEqual(finding.start_line, 12)
        self.assertEqual(finding.end_line, 13)
        self.assertEqual(finding.detector, "semgrep")

    def test_extracts_cwe_number_only(self):
        finding = semgrep_backend._to_finding(SAMPLE_JSON["results"][0], self.tmp)
        assert finding is not None
        self.assertIn("CWE-89", finding.cwe)
        self.assertNotIn("Improper Neutralization of Special Elements used in an SQL Command", " ".join(finding.cwe))

    def test_extracts_dataflow_trace(self):
        finding = semgrep_backend._to_finding(SAMPLE_JSON["results"][0], self.tmp)
        assert finding is not None
        labels = [t.label for t in finding.trace]
        self.assertIn("source", labels)
        self.assertIn("sink", labels)
        self.assertEqual(len(finding.trace), 3)
        source = next(t for t in finding.trace if t.label == "source")
        self.assertEqual(source.path, "app/api.py")
        self.assertEqual(source.line, 5)

    def test_code_line_used_for_fingerprint(self):
        finding = semgrep_backend._to_finding(SAMPLE_JSON["results"][0], self.tmp)
        assert finding is not None
        self.assertTrue(finding.code_line)
        self.assertTrue(finding.fingerprint)

    def test_bad_item_returns_none(self):
        self.assertIsNone(semgrep_backend._to_finding({}, self.tmp))
        self.assertIsNone(semgrep_backend._to_finding({"path": ""}, self.tmp))

    def test_extract_json_tolerates_log_noise(self):
        noisy = "some warning\n" + json.dumps(SAMPLE_JSON) + "\ntrailing log"
        parsed = semgrep_backend._extract_json(noisy)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(len(parsed["results"]), 1)

    def test_extract_json_returns_none_on_garbage(self):
        self.assertIsNone(semgrep_backend._extract_json("no json here"))
        self.assertIsNone(semgrep_backend._extract_json(""))


class TestAvailability(unittest.TestCase):
    def test_scan_degrades_gracefully_when_missing(self):
        """环境里没有 semgrep 时必须返回空结果 + 说明，不能抛异常。"""
        findings, note = semgrep_backend.scan(Path("."), mode="none")
        self.assertEqual(findings, [])
        self.assertTrue(note)

    def test_install_hint_mentions_platform(self):
        hint = semgrep_backend.install_hint()
        self.assertTrue(hint)
        self.assertIn("semgrep", hint.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)

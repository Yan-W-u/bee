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

    def test_duplicate_cwe_and_owasp_collapsed(self):
        """semgrep 的 metadata 里同一个 CWE/OWASP 会以不同描述出现多次。

        不去重会让 SARIF tags 违反 uniqueItems，GitHub 上传直接拒收——
        这个坑在 CI 上踩过一次，必须锁住。
        """
        meta = {
            "cwe": [
                "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                "CWE-89: SQL Injection",
                "CWE-943: Improper Neutralization",
            ],
            "owasp": ["A03:2021 - Injection", "A03:2021"],
        }
        self.assertEqual(
            semgrep_backend._cwe_list(meta),
            ["CWE-89", "CWE-943"],
        )
        self.assertEqual(semgrep_backend._owasp_list(meta), ["A03:2021"])

        item = dict(SAMPLE_JSON["results"][0])
        item["extra"] = dict(item["extra"], metadata=meta)
        finding = semgrep_backend._to_finding(item, self.tmp)
        assert finding is not None
        self.assertEqual(len(finding.cwe), len(set(finding.cwe)))
        self.assertEqual(len(finding.owasp), len(set(finding.owasp)))

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


class TestDockerCommand(unittest.TestCase):
    """docker 分支的命令拼装。

    这条路径只在装了 docker 的机器上才会走到——本地没有 docker，
    所以曾经有一个变量名拼错（NameError）一直没被发现，直到 CI 上
    docker 可用才炸。测试不依赖 docker：直接调 _build_command。
    """

    def test_command_has_readonly_mount_and_pinned_image(self):
        cmd = semgrep_backend._build_command("docker", ["docker"], Path("/tmp/repo"), "auto", ".")
        self.assertEqual(cmd[0], "docker")
        joined = " ".join(cmd)
        self.assertIn(":/src:ro", joined, "挂载必须只读，不能给容器写宿主仓库的权限")
        self.assertIn(semgrep_backend.SEMGREP_IMAGE_DEFAULT, cmd)
        self.assertNotIn(":latest", joined)
        self.assertIn("--config", cmd)

    def test_image_can_be_overridden(self):
        import os

        old = os.environ.get("BEE_SEMGREP_IMAGE")
        try:
            os.environ["BEE_SEMGREP_IMAGE"] = "my.registry/semgrep:9.9.9"
            self.assertEqual(semgrep_backend._semgrep_image(), "my.registry/semgrep:9.9.9")
        finally:
            if old is None:
                os.environ.pop("BEE_SEMGREP_IMAGE", None)
            else:
                os.environ["BEE_SEMGREP_IMAGE"] = old
        self.assertEqual(semgrep_backend._semgrep_image(), semgrep_backend.SEMGREP_IMAGE_DEFAULT)

    def test_local_mode_command(self):
        cmd = semgrep_backend._build_command("local", ["semgrep"], Path("."), "auto", ".")
        self.assertEqual(cmd[:2], ["semgrep", "--json"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

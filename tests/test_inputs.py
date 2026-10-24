"""外部 SARIF 输入（--input）的测试。

这是 bee 从「自己检测」转向「接住别人的检测结果，只负责修和验证」的接缝。
接缝错了，整个定位就落空，所以格式细节要卡死。
"""

from __future__ import annotations

import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from bee.cli import main
from bee.inputs import findings_from_sarif
from bee.models import Severity

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestSarifInput(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-sarif-in-"))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "db.py").write_text(
            'def q(cur, uid):\n    return cur.execute(f"SELECT * FROM t WHERE id = {uid}")\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parses_results(self):
        items = findings_from_sarif(FIXTURES / "semgrep.sarif", self.tmp)
        self.assertEqual(len(items), 2)
        first = items[0]
        self.assertEqual(first.rule_id, "python.lang.security.audit.formatted-sql-query")
        self.assertEqual(first.path, "app/db.py")
        self.assertEqual(first.start_line, 12)
        self.assertEqual(first.severity, Severity.ERROR)
        self.assertEqual(first.detector, "sarif")

    def test_level_falls_back_to_rule_default(self):
        # 第二条结果没有 level，规则定义里是 warning
        items = findings_from_sarif(FIXTURES / "semgrep.sarif", self.tmp)
        second = next(i for i in items if i.path == "app/files.py")
        self.assertEqual(second.severity, Severity.WARNING)

    def test_deduplicates_same_line_rule(self):
        items = findings_from_sarif(FIXTURES / "codeql.sarif", self.tmp)
        self.assertEqual(len(items), 1, "同一行同一规则重复上报必须去重")

    def test_absolute_uri_becomes_relative(self):
        sarif = self.tmp / "abs.sarif"
        target = (self.tmp / "app" / "db.py").resolve()
        sarif.write_text(
            '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[]}},'
            '"results":[{"ruleId":"r","level":"error","message":{"text":"m"},'
            '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///'
            + str(target).replace("\\", "/").lstrip("/")
            + '"},"region":{"startLine":1}}}]}]}]}',
            encoding="utf-8",
        )
        items = findings_from_sarif(sarif, self.tmp)
        self.assertEqual(items[0].path, "app/db.py")

    def test_rejects_non_sarif(self):
        bad = self.tmp / "bad.json"
        bad.write_text('{"hello": 1}', encoding="utf-8")
        with self.assertRaises(ValueError):
            findings_from_sarif(bad, self.tmp)

    def test_cli_input_skips_builtin_scan(self):
        # 目标文件本身没有内置规则命中，全靠 SARIF 提供 finding
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            code = main([
                "audit", str(self.tmp), "--no-llm",
                "--input", str(FIXTURES / "semgrep.sarif"),
            ])
        self.assertEqual(code, 0)
        # console 输出不打印 rule_id，用 SARIF 里的 message 判断来源
        self.assertIn("formatted SQL query", buf.getvalue())


class TestUnverifiedRescan(unittest.TestCase):
    """外部 finding 的 finding_gone 必须是 None，不能是 True。"""

    def test_finding_gone_is_none_for_sarif(self):
        from bee.models import PatchAttempt

        attempt = PatchAttempt(round=1, diff="")
        attempt.applied = True
        attempt.compiles = True
        attempt.finding_gone = None
        self.assertFalse(attempt.succeeded, "未重扫不能算已验证修复")
        self.assertIn("未做重扫", attempt.failure_reason())


if __name__ == "__main__":
    unittest.main()

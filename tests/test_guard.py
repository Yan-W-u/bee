"""受保护路径的回归测试。

这组用例来自一次真实的绕过：模型为了让 tests_pass 变绿，
把 test_orders.py 里的断言一起改了。如果不硬拦，
「四项信号全绿」可以靠改测试伪造出来，整套验证就没有意义了。
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from bee.verify import EditProposal, FileEdit, is_protected, verify_patch


class TestIsProtected(unittest.TestCase):
    def test_blocks_test_files(self):
        cases = [
            "test_app.py",
            "app_test.py",
            "tests/test_x.py",
            "src/__tests__/a.js",
            "web/a.test.ts",
            "web/a.spec.js",
            "svc/thing_test.go",
            "spec/models/user_spec.rb",
        ]
        for path in cases:
            self.assertTrue(is_protected(path), f"应拦截: {path}")

    def test_blocks_ci_and_build_config(self):
        cases = [
            ".github/workflows/bee.yml",
            "package.json",
            "pyproject.toml",
            "go.mod",
            "Makefile",
            "conftest.py",
            "pytest.ini",
        ]
        for path in cases:
            self.assertTrue(is_protected(path), f"应拦截: {path}")

    def test_allows_normal_source(self):
        cases = [
            "app.py",
            "orders.py",
            "src/main.go",
            "lib/util.js",
            "contest.py",
            "testimony.py",
            "service/testing_helpers.py",
        ]
        for path in cases:
            self.assertFalse(is_protected(path), f"不应拦截: {path}")


class TestVerifyRejectsProtectedEdits(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-guard-"))
        (self.tmp / "app.py").write_text(
            'import sqlite3\n\n\n'
            'def q(k):\n'
            '    conn = sqlite3.connect("x.db")\n'
            '    sql = "SELECT id FROM t WHERE a = \'" + k + "\'"\n'
            '    return conn.execute(sql).fetchall()\n',
            encoding="utf-8", newline="",
        )
        (self.tmp / "test_app.py").write_text(
            "def test_ok():\n    assert True\n", encoding="utf-8", newline="",
        )
        from bee.detect import scan_file

        findings = scan_file(self.tmp / "app.py", self.tmp)
        self.finding = next(f for f in findings if f.rule_id == "bee.sql-injection")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_patch_touching_test_file_is_rejected(self):
        proposal = EditProposal(
            file="app.py",
            edits=[
                FileEdit(
                    "app.py",
                    'sql = "SELECT id FROM t WHERE a = \'" + k + "\'"',
                    'sql = "SELECT id FROM t WHERE a = ?"',
                ),
                FileEdit("test_app.py", "assert True", "assert False  # 让它变绿"),
            ],
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertFalse(attempt.succeeded)
        self.assertIn("受保护文件", attempt.failure_reason())

    def test_normal_patch_still_passes(self):
        proposal = EditProposal(
            file="app.py",
            edits=[FileEdit(
                "app.py",
                'sql = "SELECT id FROM t WHERE a = \'" + k + "\'"',
                'sql = "SELECT id FROM t WHERE a = ?"',
            )],
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertTrue(attempt.succeeded, attempt.failure_reason())

    def test_patch_not_touching_vulnerable_file_is_rejected(self):
        (self.tmp / "other.py").write_text("x = 1\n", encoding="utf-8", newline="")
        proposal = EditProposal(
            file="other.py",
            edits=[FileEdit("other.py", "x = 1", "x = 2")],
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertFalse(attempt.succeeded)
        self.assertIn("没有修改漏洞所在文件", attempt.failure_reason())

    def test_multi_file_patch_to_callers_passes(self):
        (self.tmp / "caller.py").write_text(
            "from app import q\n\n\ndef run(v):\n    return q(v)\n",
            encoding="utf-8", newline="",
        )
        proposal = EditProposal(
            file="app.py",
            edits=[
                FileEdit(
                    "app.py",
                    'sql = "SELECT id FROM t WHERE a = \'" + k + "\'"',
                    'sql = "SELECT id FROM t WHERE a = ?"',
                ),
                FileEdit("caller.py", "return q(v)", "return q(v)  # 参数化后调用方式不变"),
            ],
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertTrue(attempt.succeeded, attempt.failure_reason())
        self.assertIn("caller.py", attempt.diff)


if __name__ == "__main__":
    unittest.main(verbosity=2)

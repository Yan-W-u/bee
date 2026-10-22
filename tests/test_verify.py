"""验证层测试：证明四项机器信号确实在起作用。

这是整个工具最需要被测试的部分。如果验证层被写成走过场，
那这个工具就退化成「让 LLM 随手改代码」，没有存在意义。
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from bee.detect import scan_file
from bee.models import Finding, Severity
from bee.verify import EditProposal, replace_once, verify_patch

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "vulnerable_app"


VULNERABLE = '''import sqlite3


def find_order(keyword):
    conn = sqlite3.connect("x.db")
    cursor = conn.cursor()
    sql = "SELECT id FROM orders WHERE note LIKE '%" + keyword + "%'"
    cursor.execute(sql)
    return cursor.fetchall()
'''

FIXED = '''import sqlite3


def find_order(keyword):
    conn = sqlite3.connect("x.db")
    cursor = conn.cursor()
    sql = "SELECT id FROM orders WHERE note LIKE ?"
    cursor.execute("SELECT id FROM orders WHERE note LIKE ?", ("%" + keyword + "%",))
    return cursor.fetchall()
'''


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-test-"))
        self.file = self.tmp / "service.py"
        self.file.write_text(VULNERABLE, encoding="utf-8", newline="")
        findings = scan_file(self.file, self.tmp)
        self.assertTrue(findings, "样本应被检出 SQL 注入")
        self.finding: Finding = next(f for f in findings if f.rule_id == "bee.sql-injection")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestReplaceOnce(Case):
    def test_refuses_ambiguous_match(self):
        source = "a = 1\na = 1\n"
        self.assertIsNone(replace_once(source, "a = 1", "a = 2"))

    def test_refuses_missing_match(self):
        self.assertIsNone(replace_once("x = 1\n", "not there", "y"))

    def test_replaces_unique_match(self):
        self.assertEqual(replace_once("x = 1\ny = 2\n", "x = 1", "x = 9"), "x = 9\ny = 2\n")


class TestVerifiedPatch(Case):
    def test_correct_patch_passes_all_signals(self):
        proposal = EditProposal(
            file="service.py",
            old_string=VULNERABLE[VULNERABLE.index("    sql ="): VULNERABLE.index("    return cursor")],
            new_string='    sql = "SELECT id FROM orders WHERE note LIKE ?"\n'
                       '    cursor.execute("SELECT id FROM orders WHERE note LIKE ?", ("%" + keyword + "%",))\n',
            rationale="改为参数化查询",
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertTrue(attempt.applied, attempt.failure_reason())
        self.assertTrue(attempt.finding_gone, attempt.failure_reason())
        self.assertTrue(attempt.compiles, attempt.failure_reason())
        self.assertTrue(attempt.succeeded, attempt.failure_reason())
        self.assertIn("@@", attempt.diff)

    def test_unmatched_old_string_blocks(self):
        proposal = EditProposal(
            file="service.py",
            old_string="this line does not exist",
            new_string="whatever",
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertFalse(attempt.applied)
        self.assertFalse(attempt.succeeded)
        self.assertIn("不唯一", attempt.failure_reason())

    def test_patch_that_keeps_vulnerability_is_rejected(self):
        """关键用例：补丁能应用、能编译，但没真正消除危险模式 —— 必须判失败。"""
        proposal = EditProposal(
            file="service.py",
            old_string='    sql = "SELECT id FROM orders WHERE note LIKE \'%" + keyword + "%\'"',
            new_string='    sql = "SELECT id FROM orders WHERE note LIKE \'%" + keyword.strip() + "%\'"',
            rationale="只做了 trim，没有参数化",
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertTrue(attempt.applied)
        self.assertTrue(attempt.compiles)
        self.assertFalse(attempt.finding_gone, "未消除危险模式却被判为修复成功")
        self.assertFalse(attempt.succeeded)

    def test_syntactically_broken_patch_is_rejected(self):
        proposal = EditProposal(
            file="service.py",
            old_string='    cursor.execute(sql)\n',
            new_string='    cursor.execute(sql\n',
            rationale="故意破坏语法",
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertTrue(attempt.applied)
        self.assertFalse(attempt.compiles, "语法错误未被检出")
        self.assertFalse(attempt.succeeded)

    def test_noop_patch_is_rejected(self):
        snippet = '    cursor.execute(sql)\n'
        proposal = EditProposal(file="service.py", old_string=snippet, new_string=snippet)
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        self.assertFalse(attempt.succeeded)
        self.assertTrue(attempt.errors)


class TestSandboxIsolation(Case):
    def test_original_file_never_modified(self):
        before = self.file.read_text(encoding="utf-8")
        proposal = EditProposal(
            file="service.py",
            old_string='    cursor.execute(sql)\n',
            new_string='    cursor.execute(sql, ())\n',
            rationale="故意错误的修法",
        )
        verify_patch(self.finding, proposal, self.tmp, 1, run_tests=False)
        after = self.file.read_text(encoding="utf-8")
        self.assertEqual(before, after, "验证过程改动了原始文件")


class TestSampleProject(Case):
    def test_sample_detects_expected_rule_set(self):
        findings = scan_file(SAMPLE / "orders.py", SAMPLE)
        rules = {f.rule_id for f in findings}
        expected = {
            "bee.sql-injection",
            "bee.command-injection",
            "bee.path-traversal",
            "bee.hardcoded-credential",
            "bee.unsafe-deserialization",
            "bee.weak-crypto",
            "bee.tls-verify-disabled",
        }
        self.assertTrue(expected.issubset(rules), f"漏检: {expected - rules}")
        self.assertTrue(all(f.severity in Severity for f in findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)

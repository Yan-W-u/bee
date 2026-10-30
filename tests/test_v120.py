"""v1.2.0 复核修复的验收测试。

对应外部复核报告 V1.1-REVIEW 的 P1–P4 与 S1：

P1  `--max-findings` 在没有 API key 时必须生效（此前被 max_llm_calls 短路）
P2  PEP 561：`bee/py.typed` 必须存在且被打进 wheel
P3  真实语料阈值收紧，门禁才抓得住渐进退化
P4  self 语料只扫 git 追踪文件，本地残留不污染门禁
S1  外部 SARIF 的 finding 通过 aliases 映射后可以真正验证「漏洞消失」
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from bee.budget import Budget
from bee.cli import main
from bee.models import Finding, PatchAttempt, Severity
from bee.verify import EditProposal, verify_patch

ROOT = Path(__file__).resolve().parent.parent

VULNERABLE = '''def q(cur, uid):
    return cur.execute(f"SELECT * FROM t WHERE id = {uid}")
'''

FIXED = '''def q(cur, uid):
    return cur.execute("SELECT * FROM t WHERE id = ?", (uid,))
'''


def make_finding(rule_id: str = "bee.sql-injection", path: str = "app.py") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.ERROR,
        message="test",
        path=path,
        start_line=2,
        end_line=2,
        code_line="",
    )


class TestBudgetWithoutKey(unittest.TestCase):
    """P1：预算分维度。

    v1.1.0 把「条数」和「模型调用」合成一个判定，无 key 时 llm_calls 永远为 0、
    max_llm_calls 检查却先返回 False，于是 --max-findings 完全失效。
    """

    def test_count_limit_applies_without_llm(self):
        b = Budget(max_findings=2, max_llm_calls=120, max_seconds=0)
        for _ in range(2):
            self.assertTrue(b.allows_count())
            b.charge(0)          # 无 key：这条 finding 消耗 0 次调用
        self.assertFalse(b.allows_count())
        self.assertIn("max-findings", b.stopped_reason)

    def test_llm_limit_not_consulted_without_llm(self):
        b = Budget(max_findings=0, max_llm_calls=1, max_seconds=0)
        b.charge(0)
        # 无 key 时不该因为「调用次数」被拦——一次调用都没发生过
        self.assertTrue(b.allows_count())

    def test_cli_max_findings_works_with_no_llm(self):
        tmp = Path(tempfile.mkdtemp(prefix="bee-p1-"))
        try:
            # 8 处独立漏洞，足够超过 --max-findings 2
            for i in range(8):
                (tmp / f"m{i}.py").write_text(
                    f"def f{i}(x):\n    return eval(x)\n", encoding="utf-8"
                )
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = main(["audit", str(tmp), "--detector", "rules", "--no-llm",
                             "--max-findings", "2", "--json"])
            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            explained = [d for d in data if d["status"] != "skipped"]
            skipped = [d for d in data if d["status"] == "skipped"]
            self.assertEqual(len(explained), 2, "无 key 时 --max-findings 必须生效")
            self.assertEqual(len(skipped), 6)
            self.assertTrue(all("max-findings" in d["skipped_reason"] for d in skipped))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPyTyped(unittest.TestCase):
    """P2：声明了 Typing :: Typed 就必须带 py.typed。"""

    def test_marker_exists(self):
        self.assertTrue((ROOT / "bee" / "py.typed").is_file(),
                        "classifier 声明了 Typed，缺 py.typed 等于声明大于实现")

    def test_package_data_declared(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[tool.setuptools.package-data]", text)
        self.assertIn('bee = ["py.typed"]', text)

    def test_classifier_and_marker_agree(self):
        # 二选一：要么删 classifier，要么留 py.typed。这里锁住「留文件」这条路
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        if "Typing :: Typed" in text:
            self.assertTrue((ROOT / "bee" / "py.typed").is_file())


class TestRealworldGate(unittest.TestCase):
    """P3/P4：阈值收紧 + self 语料只扫 git 追踪文件。"""

    def test_stdlib_threshold_is_tight(self):
        data = json.loads((ROOT / "benchmark" / "expected.json").read_text(encoding="utf-8"))
        limit = data["python-stdlib"]["max_findings"]
        current = data["python-stdlib"]["current_v1_1_0"]
        self.assertLessEqual(limit, 110, "阈值放太宽，门禁抓不到渐进退化")
        self.assertGreater(limit, current)
        self.assertLessEqual((limit - current) / current, 0.4, "余量超过 40% 等于没设门禁")

    def test_self_corpus_uses_git_tracked(self):
        specs = json.loads((ROOT / "benchmark" / "corpora.json").read_text(encoding="utf-8"))
        self_spec = next(c for c in specs["corpora"] if c["name"] == "self")
        self.assertTrue(self_spec.get("git_tracked"),
                        "self 语料全目录扫描时，本地 tmp/build 残留会让门禁随机变红")

    def test_git_tracked_ignores_untracked(self):
        from benchmark.realworld import _git_tracked

        tracked = _git_tracked(ROOT)
        if not tracked:
            self.skipTest("当前环境不是 git 仓库")
        self.assertNotIn("tmp/dirty.py", tracked)
        self.assertIn("bee/cli.py", tracked)


class TestAliasRescan(unittest.TestCase):
    """S1：外部 finding 映射到本地规则后才能验证「漏洞消失」。"""

    def test_explicit_mapping(self):
        from bee.aliases import resolve

        known = {"bee.sql-injection"}
        target, guess = resolve("python.lang.security.audit.formatted-sql-query", known)
        self.assertEqual(target, "bee.sql-injection")
        self.assertFalse(guess, "人工核对过的映射不该标成猜测")

    def test_codeql_mapping(self):
        from bee.aliases import resolve

        self.assertEqual(resolve("py/sql-injection", {"bee.sql-injection"})[0], "bee.sql-injection")

    def test_unknown_rule_stays_unmapped(self):
        from bee.aliases import resolve

        self.assertEqual(resolve("org.custom.weird-thing", {"bee.sql-injection"}), ("", False))

    def test_guess_only_when_allowed(self):
        from bee.aliases import resolve

        rid = "acme.rules.audit.sql-string-format"
        self.assertEqual(resolve(rid, {"bee.sql-injection"}), ("", False))
        target, guess = resolve(rid, {"bee.sql-injection"}, allow_guess=True)
        self.assertEqual(target, "bee.sql-injection")
        self.assertTrue(guess)

    def test_sarif_finding_is_not_rescan_ok_by_default(self):
        from bee.aliases import annotate
        from bee.inputs import findings_from_sarif

        tmp = Path(tempfile.mkdtemp(prefix="bee-alias-"))
        try:
            (tmp / "app").mkdir()
            (tmp / "app" / "db.py").write_text(VULNERABLE, encoding="utf-8")
            items = findings_from_sarif(
                Path(__file__).resolve().parent / "fixtures" / "semgrep.sarif", tmp
            )
            self.assertTrue(items)
            self.assertTrue(all(not f.rescan_ok for f in items),
                            "外部规则默认不可重扫，否则扫不到会被当成已修复")
            annotate(items, {"bee.sql-injection"}, allow_guess=False)
            mapped = [f for f in items if f.rescan_ok]
            self.assertEqual(len(mapped), 1)
            self.assertEqual(mapped[0].rescan_id, "bee.sql-injection")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_unmapped_finding_never_reports_verified(self):
        """关键用例：映射不上的外部 finding，补丁再正确也只能是「未验证」。"""
        tmp = Path(tempfile.mkdtemp(prefix="bee-unmapped-"))
        try:
            f = tmp / "app.py"
            f.write_text(VULNERABLE, encoding="utf-8", newline="")
            finding = make_finding(rule_id="org.custom.weird-thing")
            finding.rescan_ok = False
            proposal = EditProposal(
                file="app.py",
                old_string='    return cur.execute(f"SELECT * FROM t WHERE id = {uid}")',
                new_string='    return cur.execute("SELECT * FROM t WHERE id = ?", (uid,))',
                rationale="参数化",
            )
            attempt = verify_patch(finding, proposal, tmp, 1, run_tests=False)
            self.assertTrue(attempt.applied)
            self.assertTrue(attempt.compiles)
            self.assertIsNone(attempt.finding_gone, "没有等价规则时重扫结论必须是 None")
            self.assertFalse(attempt.succeeded, "未验证的补丁不能算 verified")
            self.assertTrue(any("未做" in n for n in attempt.notes))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mapped_finding_gets_real_verdict(self):
        """映射成功后，同一个补丁能拿到 finding_gone=True。"""
        tmp = Path(tempfile.mkdtemp(prefix="bee-mapped-"))
        try:
            (tmp / "app.py").write_text(VULNERABLE, encoding="utf-8", newline="")
            finding = make_finding(rule_id="python.lang.security.audit.formatted-sql-query")
            finding.rescan_rule_id = "bee.sql-injection"
            finding.rescan_ok = True
            proposal = EditProposal(
                file="app.py",
                old_string='    return cur.execute(f"SELECT * FROM t WHERE id = {uid}")',
                new_string='    return cur.execute("SELECT * FROM t WHERE id = ?", (uid,))',
                rationale="参数化",
            )
            attempt = verify_patch(finding, proposal, tmp, 1, run_tests=False)
            self.assertTrue(attempt.finding_gone, attempt.failure_reason())
            self.assertTrue(attempt.succeeded, attempt.failure_reason())
            self.assertTrue(any("映射" in n for n in attempt.notes))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_patch_that_keeps_vuln_still_fails_under_alias(self):
        """映射不是「放行」：没修好照样判失败。"""
        tmp = Path(tempfile.mkdtemp(prefix="bee-mapped-bad-"))
        try:
            (tmp / "app.py").write_text(VULNERABLE, encoding="utf-8", newline="")
            finding = make_finding(rule_id="py/sql-injection")
            finding.rescan_rule_id = "bee.sql-injection"
            proposal = EditProposal(
                file="app.py",
                old_string="{uid}",
                new_string="{uid.strip()}",
                rationale="只 trim",
            )
            attempt = verify_patch(finding, proposal, tmp, 1, run_tests=False)
            self.assertFalse(attempt.finding_gone)
            self.assertFalse(attempt.succeeded)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSarifMetadata(unittest.TestCase):
    """外部 SARIF 的 CWE / OWASP / helpUri 在规则级，不能丢。"""

    def test_reads_rule_level_tags(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Semgrep", "rules": [{
                    "id": "python.lang.security.audit.formatted-sql-query",
                    "defaultConfiguration": {"level": "error"},
                    "helpUri": "https://semgrep.dev/r/sqli",
                    "properties": {"tags": [
                        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                        "OWASP-A03:2021 - Injection",
                        "security",
                    ]},
                }]}},
                "results": [{
                    "ruleId": "python.lang.security.audit.formatted-sql-query",
                    "message": {"text": "formatted sql"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "app/db.py"},
                        "region": {"startLine": 2}}}],
                }],
            }],
        }
        tmp = Path(tempfile.mkdtemp(prefix="bee-meta-"))
        try:
            p = tmp / "s.sarif"
            p.write_text(json.dumps(sarif), encoding="utf-8")
            from bee.inputs import findings_from_sarif

            f = findings_from_sarif(p, tmp)[0]
            self.assertIn("CWE-89", f.cwe)
            self.assertIn("A03:2021", f.owasp)
            self.assertTrue(any("semgrep.dev" in r for r in f.references))
            self.assertEqual(f.severity, Severity.ERROR)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_codeql_external_cwe_tag(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "rules": [{
                    "id": "py/sql-injection",
                    "properties": {"tags": ["external/cwe/cwe-089", "security"]},
                }]}},
                "results": [{
                    "ruleId": "py/sql-injection",
                    "message": {"text": "m"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": 1}}}],
                }],
            }],
        }
        tmp = Path(tempfile.mkdtemp(prefix="bee-meta2-"))
        try:
            p = tmp / "s.sarif"
            p.write_text(json.dumps(sarif), encoding="utf-8")
            from bee.inputs import findings_from_sarif

            f = findings_from_sarif(p, tmp)[0]
            self.assertEqual(f.cwe, ["CWE-89"], "CodeQL 用 external/cwe/cwe-089 的写法")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestVersionConsistency(unittest.TestCase):
    """版本号两处手写（pyproject + bee/__init__），必须有测试防止漂移。"""

    def test_versions_match(self):
        import tomllib

        import bee

        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["version"], bee.__version__,
                         "改了 __init__ 忘改 pyproject（或反之），发出去的包版本会错")


if __name__ == "__main__":
    unittest.main()

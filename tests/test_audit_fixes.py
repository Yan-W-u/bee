"""外部审计修复的验收测试。

对应 FIX-LIST 的 Definition of Done：每一条都是「审计说会坑人的场景」，
必须在测试里真实发生过一次，才算修掉。
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from bee.cli import main
from bee.detect import Rule, glob_to_regex, matches_globs, scan_file, scan_tree
from bee.explain import _validate
from bee.models import Explanation, Finding, Severity
from bee.verify import (
    EditProposal, PatchSession, apply_session, is_protected,
    safe_join, sanitized_env, verify_patch,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))


def make_finding(**kwargs) -> Finding:
    base = dict(
        rule_id="bee.hardcoded-credential",
        severity=Severity.WARNING,
        message="硬编码凭据",
        path="app.py",
        start_line=3,
        end_line=3,
        cwe=["CWE-798"],
        owasp=["A07:2021"],
        snippet='password = "prod_secret"',
        code_line='password = "prod_secret"',
        raw={},
    )
    base.update(kwargs)
    return Finding(**base)


class _CtxStub:
    """explain._validate 只用到 line_range() 与 callers。"""

    def __init__(self, lo: int, hi: int, callers: list | None = None) -> None:
        self._range = (lo, hi)
        self.callers = callers or []

    def line_range(self) -> tuple[int, int]:
        return self._range


class _CallerStub:
    def __init__(self, path: str, line: int) -> None:
        self.path = path
        self.line = line


class TestGlobSemantics(unittest.TestCase):
    """--exclude 的 ** 语义。以前 glob 根本没接进扫描，这一层是空谈。"""

    def test_double_star_matches_nested(self):
        self.assertTrue(matches_globs("tests/unit/test_x.py", ["tests/**"]))
        self.assertTrue(matches_globs("tests/test_x.py", ["tests/**"]))
        self.assertFalse(matches_globs("src/tests_like.py", ["tests/**"]))

    def test_double_star_slash_matches_zero_dirs(self):
        rx = glob_to_regex("src/**/*.py")
        self.assertTrue(rx.match("src/a.py"))
        self.assertTrue(rx.match("src/a/b/c.py"))
        self.assertFalse(rx.match("src/a.js"))

    def test_single_star_does_not_cross_dirs(self):
        self.assertFalse(matches_globs("a/b/c.py", ["a/*.py"]))
        self.assertTrue(matches_globs("a/b.py", ["a/*.py"]))

    def test_scan_tree_excludes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "src" / "app.py").write_text(
                'API_KEY = "sk_live_abcdef123456"\n', encoding="utf-8"
            )
            (root / "tests" / "test_app.py").write_text(
                'API_KEY = "sk_live_abcdef123456"\n', encoding="utf-8"
            )
            all_hits = scan_tree(root)
            self.assertTrue(any(f.path.startswith("tests/") for f in all_hits))
            filtered = scan_tree(root, exclude_globs=["tests/**"])
            self.assertFalse(any(f.path.startswith("tests/") for f in filtered))
            self.assertTrue(any(f.path.startswith("src/") for f in filtered))

    def test_cli_exclude_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "test_leak.py").write_text(
                'API_KEY = "sk_live_abcdef123456"\n', encoding="utf-8"
            )
            (root / "app.py").write_text(
                'API_KEY = "sk_live_abcdef123456"\n', encoding="utf-8"
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["scan", str(root), "--detector", "rules", "--exclude", "tests/**", "--json"])
            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            paths = [f["path"] for f in data]
            self.assertNotIn("tests/test_leak.py", paths)
            self.assertIn("app.py", paths)


class TestBaselineDifferential(unittest.TestCase):
    """P0-1：项目原有测试就是红的，补丁不能被误判「破坏功能」。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-p01-"))
        (self.tmp / "app.py").write_text(
            'import os\n\nAPI_TOKEN = "prod_api_token_9f3c1a77"\n', encoding="utf-8"
        )
        # 一个必失败的测试：项目本身的红，与补丁无关
        (self.tmp / "test_broken.py").write_text(
            "import unittest\n\n\nclass T(unittest.TestCase):\n"
            "    def test_always_fails(self):\n        self.fail('本来就坏')\n",
            encoding="utf-8",
        )
        findings = scan_tree(self.tmp)
        self.finding = next(f for f in findings if f.rule_id == "bee.hardcoded-credential")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_red_baseline_is_unavailable_not_patch_failure(self):
        proposal = EditProposal(
            file="app.py",
            old_string='API_TOKEN = "prod_api_token_9f3c1a77"',
            new_string='API_TOKEN = os.environ.get("API_TOKEN", "")',
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1, run_tests=True)
        self.assertTrue(attempt.applied, attempt.failure_reason())
        self.assertTrue(attempt.finding_gone, attempt.failure_reason())
        self.assertTrue(attempt.succeeded, attempt.failure_reason())
        self.assertIsNone(attempt.tests_pass, "红基线应记「不可用」(None) 而不是 False")
        self.assertTrue(any("不可用" in n or "已失败" in n for n in attempt.notes),
                        f"notes 应说明基线不可用: {attempt.notes}")


class TestCustomRulesFindingGone(unittest.TestCase):
    """P0-2：自定义规则的 finding 必须用同一规则集重扫。"""

    CUSTOM = [Rule(
        id="myorg.internal-key",
        title="内部密钥硬编码",
        severity=Severity.ERROR,
        cwe=["CWE-798"],
        owasp=[],
        languages=["python"],
        pattern=r'INTERNAL_KEY\s*=\s*"myorg-[a-f0-9]{16}"',
    )]

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-p02-"))
        (self.tmp / "app.py").write_text(
            'import os\n\nINTERNAL_KEY = "myorg-0123456789abcdef"\nprint(1)\n', encoding="utf-8"
        )
        hits = scan_file(self.tmp / "app.py", self.tmp, self.CUSTOM)
        self.assertEqual(len(hits), 1)
        self.finding = hits[0]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_noop_patch_fails_finding_gone(self):
        # 无关改动：漏洞原样保留
        proposal = EditProposal(
            file="app.py",
            old_string="print(1)",
            new_string="print(2)",
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1,
                               run_tests=False, rules=self.CUSTOM)
        self.assertTrue(attempt.applied)
        self.assertFalse(attempt.finding_gone, "漏洞仍在，finding_gone 必须是 False")
        self.assertFalse(attempt.succeeded)

    def test_real_patch_passes(self):
        proposal = EditProposal(
            file="app.py",
            old_string='INTERNAL_KEY = "myorg-0123456789abcdef"',
            new_string='INTERNAL_KEY = os.environ.get("INTERNAL_KEY", "")',
        )
        attempt = verify_patch(self.finding, proposal, self.tmp, 1,
                               run_tests=False, rules=self.CUSTOM)
        self.assertTrue(attempt.applied, attempt.failure_reason())
        self.assertTrue(attempt.finding_gone, attempt.failure_reason())
        self.assertTrue(attempt.succeeded, attempt.failure_reason())


class TestEvidenceValidation(unittest.TestCase):
    """P0-4：编造证据必须被打回。"""

    SOURCE = (
        "import os\n"
        "\n"
        "def handler(token):\n"
        "    sql = 'SELECT * FROM t WHERE k = ' + token\n"
        "    return db.execute(sql)\n"
        "\n"
        "CALL = handler\n"
    )

    def _validate_evidence(self, evidence: list[str], callers: list | None = None) -> list[str]:
        expl = Explanation(
            root_cause="第 4 行 token 直接拼进 SQL 文本，足够长的根因描述。",
            attack_path="外部参数 token 进入 handler 后未参数化直达 execute，路径完整。",
            impact="可读取整库数据表，影响面明确。",
            fix_rationale="改为占位符参数绑定，语义边界由驱动维护。",
            confidence=0.9,
            evidence=evidence,
        )
        lines = self.SOURCE.splitlines()
        ctx = _CtxStub(3, 5, callers)
        return _validate(expl, make_finding(), lines, ctx)

    def test_free_text_evidence_rejected(self):
        problems = self._validate_evidence(["我随便写的结论"])
        self.assertTrue(any("格式" in p for p in problems), problems)

    def test_out_of_range_line_rejected(self):
        problems = self._validate_evidence(["L99999: 不存在的行"])
        self.assertTrue(problems, "超范围行号必须被打回")

    def test_outside_function_rejected(self):
        # 第 2 行是空行且在函数外
        problems = self._validate_evidence(["L2: 空行当证据"])
        self.assertTrue(problems)

    def test_fabricated_caller_line_rejected(self):
        # 第 7 行非空、在函数外、也不是 ctx 里登记的调用方行 → 编造
        problems = self._validate_evidence(["L7: 某个编造的调用方"])
        self.assertTrue(problems)

    def test_registered_caller_line_passes(self):
        # 跨文件调用方也合法：prompt 里调用方片段用的是各文件自己的行号
        callers = [_CallerStub("tests/test_x.py", 7)]
        problems = self._validate_evidence(["L7: 调用方以字符串常量传参"], callers)
        self.assertEqual(problems, [])

    def test_valid_evidence_passes(self):
        problems = self._validate_evidence(["L4: token 拼接进 SQL 文本"])
        self.assertEqual(problems, [])

    def test_import_region_evidence_passes(self):
        # import 区是合法证据（修复常需要补 import）
        problems = self._validate_evidence(["L1: 当前只导入了 os"])
        self.assertEqual(problems, [])


class TestSafeJoin(unittest.TestCase):
    """P1-2：模型给的路径不能越出项目根。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-sj-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rejects_dot_dot(self):
        with self.assertRaises(ValueError):
            safe_join(self.tmp, "../../etc/passwd")

    def test_rejects_absolute(self):
        with self.assertRaises(ValueError):
            safe_join(self.tmp, "/etc/passwd")
        with self.assertRaises(ValueError):
            safe_join(self.tmp, "C:/Windows/system32/config")

    def test_rejects_drive_relative_windows(self):
        # Windows 上 "//server/share" 或盘符形式
        with self.assertRaises(ValueError):
            safe_join(self.tmp, "\\\\server\\share\\evil")

    def test_accepts_normal_relative(self):
        target = safe_join(self.tmp, "src/app.py")
        self.assertTrue(str(target).startswith(str(self.tmp.resolve())))

    def test_verify_patch_rejects_escaping_file(self):
        (self.tmp / "app.py").write_text(
            'API_TOKEN = "prod_api_token_9f3c1a77"\n', encoding="utf-8"
        )
        finding = next(
            f for f in scan_tree(self.tmp) if f.rule_id == "bee.hardcoded-credential"
        )
        proposal = EditProposal(
            file="../../outside.py",
            old_string="x",
            new_string="y",
        )
        attempt = verify_patch(finding, proposal, self.tmp, 1, run_tests=False)
        self.assertFalse(attempt.applied)
        self.assertTrue(any("越出项目根" in e or "绝对路径" in e or "无法读取" in e
                            for e in attempt.errors), attempt.errors)


class TestProtectedPaths(unittest.TestCase):
    """P1-4：保护名单的缺口与大小写绕过。"""

    def test_env_and_key_files(self):
        for rel in (".env", ".env.production", "secrets/private.pem",
                    "deploy/server.key", "config/id_rsa"):
            self.assertTrue(is_protected(rel), f"应拦截: {rel}")

    def test_git_dir(self):
        self.assertTrue(is_protected(".git/config"))
        self.assertTrue(is_protected(".git/hooks/pre-commit"))

    def test_case_insensitive_ci_dir(self):
        self.assertTrue(is_protected(".GITHUB/workflows/evil.yml"))
        self.assertTrue(is_protected(".Github/workflows/evil.yml"))

    def test_build_configs(self):
        for rel in ("setup.py", "requirements.txt", "Dockerfile",
                    ".gitlab-ci.yml", ".pre-commit-hooks.yaml"):
            self.assertTrue(is_protected(rel), f"应拦截: {rel}")


class TestSymlinkGuard(unittest.TestCase):
    """P1-3：落盘不能穿过符号链接。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-sl-"))
        self.outside = Path(tempfile.mkdtemp(prefix="bee-out-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def _try_symlink(self) -> bool:
        victim = self.outside / "victim.py"
        victim.write_text("original = 1\n", encoding="utf-8")
        link = self.tmp / "app.py"
        try:
            link.symlink_to(victim)
        except (OSError, NotImplementedError):
            return False
        return True

    def test_apply_session_refuses_symlink(self):
        if not self._try_symlink():
            self.skipTest("此环境无法创建符号链接")
        session = PatchSession(self.tmp)
        session.commit(EditProposal(
            file="app.py",
            old_string="original = 1",
            new_string="original = 2",
        ))
        written, errors = apply_session(self.tmp, session)
        self.assertEqual(written, 0)
        self.assertTrue(any("符号链接" in e for e in errors), errors)
        # 受害文件必须原样
        self.assertEqual((self.outside / "victim.py").read_text(encoding="utf-8"),
                         "original = 1\n")


class TestSanitizedEnv(unittest.TestCase):
    """P1-1：子进程不能继承密钥。"""

    def test_strips_secrets(self):
        saved = {k: os.environ.get(k) for k in
                 ("BEE_LLM_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "MY_SERVICE_TOKEN")}
        try:
            os.environ["BEE_LLM_API_KEY"] = "sk-test-123"
            os.environ["AWS_SECRET_ACCESS_KEY"] = "aws-secret"
            os.environ["GITHUB_TOKEN"] = "ghp-test"
            os.environ["MY_SERVICE_TOKEN"] = "svc-token"
            os.environ["HARMLESS_VAR"] = "ok"
            env = sanitized_env()
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertNotIn("BEE_LLM_API_KEY", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("MY_SERVICE_TOKEN", env)
        self.assertIn("HARMLESS_VAR", env)


class TestScanOutputAndExitCodes(unittest.TestCase):
    """P2-7 / P2-8：scan -o 生效；--fail-on-findings 控制退出码。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-cli-"))
        (self.tmp / "app.py").write_text(
            'API_TOKEN = "prod_api_token_9f3c1a77"\n', encoding="utf-8"
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_writes_report(self):
        out = self.tmp / "report.md"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["scan", str(self.tmp), "--detector", "rules", "-o", str(out)])
        self.assertEqual(code, 0)
        self.assertTrue(out.exists())
        content = out.read_text(encoding="utf-8")
        self.assertIn("漏洞扫描报告", content)
        self.assertIn("bee.hardcoded-credential", content)

    def test_fail_on_findings_exit_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["scan", str(self.tmp), "--detector", "rules", "--fail-on-findings"])
        self.assertEqual(code, 1)

    def test_clean_project_exit_zero(self):
        clean = Path(tempfile.mkdtemp(prefix="bee-clean-"))
        try:
            (clean / "ok.py").write_text("x = 1\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["scan", str(clean), "--detector", "rules", "--fail-on-findings"])
            self.assertEqual(code, 0)
        finally:
            shutil.rmtree(clean, ignore_errors=True)

    def test_single_file_target_only_scans_that_file(self):
        other = self.tmp / "other.py"
        other.write_text('API_TOKEN = "prod_api_token_9f3c1a77"\n', encoding="utf-8")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["scan", str(self.tmp / "app.py"), "--detector", "rules", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        paths = {f["path"] for f in data}
        self.assertEqual(paths, {"app.py"})


class TestMergeFindingsKeepsDistinctRules(unittest.TestCase):
    """P2-11：同一行两种规则都得保留。"""

    def test_same_line_different_rules_both_kept(self):
        # 同一行既有硬编码凭据又是弱加密的场景构造不出来也没关系：
        # 用两个不同 rule_id 的 finding 模拟双后端合并
        f1 = make_finding(rule_id="bee.hardcoded-credential", start_line=5)
        f2 = make_finding(rule_id="semgrep.python.audit.key", start_line=5)
        from bee.detect import merge_findings
        merged = merge_findings([f1], [f2])
        ids = {f.rule_id for f in merged}
        self.assertEqual(ids, {"bee.hardcoded-credential", "semgrep.python.audit.key"})


if __name__ == "__main__":
    unittest.main()

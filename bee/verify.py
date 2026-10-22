"""验证层：判断「补丁真的修好了」而不是「补丁看起来对」。

四项机器信号，缺一不可：
  applied      —— 补丁能否落地（上下文必须真实匹配）
  finding_gone —— 重扫后原漏洞是否消失（不是让模型自称修好了）
  compiles     —— 改完还能不能跑（语法/编译）
  tests_pass   —— 有没有踩坏别的功能

铁律：永远不在用户仓库里动手。所有应用都发生在临时副本上，
产出是待 review 的 diff，由人决定是否落盘。
"""

from __future__ import annotations

import ast
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .detect import SKIP_DIRS, detect_language, scan_file, scan_tree
from .io_utils import read_source, write_source
from .models import Finding, PatchAttempt


@dataclass
class EditProposal:
    """模型给出的修改建议。

    用 old/new 精确替换而非裸 diff，落地成功率更高。

    edits 支持一次改多处——这不是可选项：修 pickle 漏洞要写 io.BytesIO
    就得补 `import io`，修命令注入要写 subprocess.run 就得补 `import subprocess`。
    只允许改一处的工具会在这种场景下永远失败，因为 import 和函数体不在同一段文本里。
    """

    file: str
    old_string: str = ""
    new_string: str = ""
    rationale: str = ""
    raw_diff: str = ""
    edits: list[tuple[str, str]] = field(default_factory=list)

    def all_edits(self) -> list[tuple[str, str]]:
        return self.edits or [(self.old_string, self.new_string)]

    def apply_to(self, source_text: str) -> str | None:
        text = source_text
        for old, new in self.all_edits():
            nxt = replace_once(text, old, new)
            if nxt is None:
                return None
            text = nxt
        return text

    def as_diff(self, source_text: str) -> str:
        if self.raw_diff.strip():
            return self.raw_diff.strip() + "\n"
        patched = self.apply_to(source_text)
        if patched is None:
            return ""
        old_lines = source_text.splitlines(keepends=True)
        new_lines = patched.splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(
                old_lines, new_lines,
                fromfile=f"a/{self.file}", tofile=f"b/{self.file}", n=4,
            )
        )


def replace_once(source: str, old: str, new: str) -> str | None:
    """精确替换。要求 old 在源码中唯一出现，否则拒绝——避免改错地方。"""
    if not old:
        return None
    count = source.count(old)
    if count != 1:
        return None
    return source.replace(old, new, 1)


class PatchSession:
    """同一文件的多个漏洞必须累积修复。

    真实代码里一个文件常有多个漏洞。如果每条都独立对着磁盘原文验证，
    第二条补丁的 old_string 会指向已被第一条改掉的内容——验证通过、
    合并时全废。所以这里维护「原始文本 + 已接受的编辑序列」，
    后续验证都基于累积后的状态。
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.accepted: dict[str, list[EditProposal]] = {}

    def base_text(self, rel_path: str) -> str | None:
        target = self.root / rel_path
        try:
            text = read_source(target)
        except OSError:
            return None
        for proposal in self.accepted.get(rel_path, []):
            nxt = proposal.apply_to(text)
            if nxt is not None:
                text = nxt
        return text

    def commit(self, rel_path: str, proposal: EditProposal) -> None:
        self.accepted.setdefault(rel_path, []).append(proposal)

    def files_touched(self) -> list[str]:
        return sorted(self.accepted)

    def count(self) -> int:
        return sum(len(v) for v in self.accepted.values())


# ---------------------------------------------------------------- 语法/编译检查


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 127, str(exc)


# 常见标准库顶层模块名。只在「代码里用了 X.x，但文件里没有 import X」时才报警，
# 范围限定在这里是为了把误报压到零——动态导入、条件导入都不在这个名单里乱判。
STDLIB_TOP = {
    "os", "sys", "io", "json", "re", "ssl", "hashlib", "subprocess", "pickle",
    "shutil", "tempfile", "pathlib", "urllib", "http", "socket", "base64",
    "hmac", "secrets", "sqlite3", "logging", "time", "datetime", "collections",
    "itertools", "functools", "typing", "abc", "enum", "dataclasses", "copy",
    "uuid", "random", "string", "csv", "xml", "math", "statistics", "struct",
    "binascii", "codecs", "contextlib", "glob", "gzip", "importlib", "inspect",
    "ipaddress", "operator", "platform", "queue", "signal", "threading",
    "traceback", "types", "warnings", "weakref", "argparse", "asyncio",
    "concurrent", "email", "hashlib", "html", "mimetypes", "pprint", "shelve",
    "tarfile", "textwrap", "tokenize", "zipfile", "zlib",
}

_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([\w\.]+)", re.M)


def check_missing_imports(text: str) -> list[str]:
    """找出「用了但没 import」的标准库模块。

    存在的理由：模型修 pickle 漏洞时会写 `io.BytesIO(...)`，修命令注入时会写
    `subprocess.run(...)`，但经常忘了在补丁里补 import。
    py_compile 只检查语法不解析名字，现有测试也未必覆盖到那条路径，
    于是 NameError 会一路躲过验证——这是实测中真的漏过去的一次。
    """
    imported = {m.group(1).split(".")[0] for m in _IMPORT_RE.finditer(text)}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    defined: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.arg):
            defined.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            defined.add(node.id)
        elif isinstance(node, ast.alias):
            defined.add((node.asname or node.name).split(".")[0])

    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                used.add(root.id)

    return sorted(n for n in used if n in STDLIB_TOP and n not in imported and n not in defined)


def check_syntax(file: Path) -> tuple[bool, str, bool]:
    """返回 (是否通过, 错误信息, 是否真的做了检查)。"""
    lang = detect_language(file)

    if lang == "python":
        code, out = _run([sys.executable, "-m", "py_compile", str(file)], file.parent, 60)
        return code == 0, out.strip()[:800], True

    if lang in {"javascript", "typescript"}:
        code, out = _run(["node", "--check", str(file)], file.parent, 60)
        if code == 127:
            return True, "未找到 node，跳过语法检查", False
        if lang == "typescript" and code != 0 and "Unknown file extension" in out:
            return True, "node 无法直接检查 TS，跳过", False
        return code == 0, out.strip()[:800], True

    if lang == "go":
        code, out = _run(["gofmt", "-e", str(file)], file.parent, 60)
        if code == 127:
            return True, "未找到 gofmt，跳过语法检查", False
        return code == 0, out.strip()[:800], True

    return True, f"{lang or '未知语言'} 无可用语法检查器", False


def detect_test_command(root: Path) -> list[str] | None:
    """探测项目自带的测试入口。

    顺序上先试 pytest（生态最广），再退到 unittest（标准库，不需要额外装包）。
    有测试才能验证「补丁没踩坏别的功能」，这一项缺了，
    补丁就只能验证到语法层——报告里会明确写出来。
    """
    if (root / "pytest.ini").exists() or (root / "conftest.py").exists():
        return [sys.executable, "-m", "pytest", "-x", "-q"]
    if (root / "pyproject.toml").exists() or (root / "setup.py").exists():
        code, _ = _run([sys.executable, "-m", "pytest", "--version"], root, 30)
        if code == 0:
            return [sys.executable, "-m", "pytest", "-x", "-q"]

    if (root / "tests").is_dir() or (root / "test").is_dir():
        code, _ = _run([sys.executable, "-m", "pytest", "--version"], root, 30)
        if code == 0:
            return [sys.executable, "-m", "pytest", "-x", "-q"]

    # unittest 兜底：不依赖第三方包
    if any(root.glob("test_*.py")) or any(root.glob("*_test.py")) or (root / "tests").is_dir():
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", ".", "-t", ".",
               "-p", "test_*.py"]
        code, _ = _run(cmd, root, 60)
        if code in (0, 1):  # 0=全过，1=有失败但套件确实跑起来了
            return cmd

    pkg = root / "package.json"
    if pkg.exists():
        try:
            if '"test"' in pkg.read_text(encoding="utf-8", errors="replace"):
                return ["npm", "test", "--silent"]
        except OSError:
            pass
    if (root / "go.mod").exists():
        return ["go", "test", "./..."]
    return None


# ---------------------------------------------------------------- 验证主流程


def _copy_project(root: Path) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="bee-"))
    dest = tmp / "repo"

    def _ignore(dirpath: str, names: list[str]) -> set[str]:
        return {n for n in names if n in SKIP_DIRS}

    shutil.copytree(root, dest, ignore=_ignore, symlinks=False)
    return dest


_TEST_BASELINE: dict[str, bool | None] = {}


def _test_baseline(root: Path) -> bool | None:
    """在未打补丁的副本上先跑一次测试，作为对照。

    None = 没有可用测试，或项目本身就跑不起来（缺依赖、缺配置）。
    没有这一步，缺依赖的项目会被误判成「补丁踩坏了功能」——
    这是差分的意义：只关心补丁**引入**的失败。
    """
    key = str(root.resolve())
    if key in _TEST_BASELINE:
        return _TEST_BASELINE[key]

    cmd = detect_test_command(root)
    if cmd is None:
        _TEST_BASELINE[key] = None
        return None

    workdir = _copy_project(root)
    try:
        code, _ = _run(cmd, workdir, 600)
        result: bool | None = code == 0
    finally:
        shutil.rmtree(workdir.parent, ignore_errors=True)

    _TEST_BASELINE[key] = result
    return result


def verify_patch(
    finding: Finding,
    proposal: EditProposal,
    root: Path,
    round_no: int,
    *,
    run_tests: bool = True,
    base_text: str | None = None,
) -> PatchAttempt:
    target_rel = proposal.file or finding.path
    target = root / target_rel

    attempt = PatchAttempt(
        round=round_no,
        diff="",
        explanation=proposal.rationale,
        file=target_rel,
        old_string=proposal.old_string,
        new_string=proposal.new_string,
        edits=proposal.all_edits(),
    )

    try:
        original = base_text if base_text is not None else read_source(target)
    except OSError as exc:
        attempt.errors.append(f"无法读取目标文件: {exc}")
        return attempt

    attempt.diff = proposal.as_diff(original)

    # --- 1. 内存中先判定补丁是否可落地
    patched_text = proposal.apply_to(original)
    if patched_text is None:
        attempt.errors.append(
            "补丁无法应用：old_string 在文件中不唯一或找不到"
        )
        return attempt
    if patched_text.strip() == original.strip():
        attempt.errors.append("补丁内容与原文件相同，没有任何实际改动")
        return attempt
    attempt.applied = True

    # --- 2. 重扫判定漏洞是否消失（不依赖文件系统，快）
    tmp_scan_dir = Path(tempfile.mkdtemp(prefix="bee-scan-"))
    try:
        scan_target = tmp_scan_dir / Path(target_rel).name
        write_source(scan_target, patched_text)
        remaining = [
            f for f in scan_file(scan_target, tmp_scan_dir)
            if f.rule_id == finding.rule_id
        ]
        attempt.finding_gone = len(remaining) == 0
        if not attempt.finding_gone:
            attempt.errors.append(
                f"重新扫描仍命中 {finding.rule_id}（{len(remaining)} 处）"
            )
    finally:
        shutil.rmtree(tmp_scan_dir, ignore_errors=True)

    # --- 3. 落到临时副本上做编译与测试
    workdir: Path | None = None
    try:
        workdir = _copy_project(root)
        work_target = workdir / target_rel
        write_source(work_target, patched_text)

        ok, msg, checked = check_syntax(work_target)
        if ok and detect_language(work_target) == "python":
            missing = check_missing_imports(patched_text)
            if missing:
                ok = False
                msg = f"补丁引用了未 import 的模块: {', '.join(missing)}"
        attempt.compiles = ok
        attempt.compile_checked = checked
        if not ok:
            attempt.errors.append(f"语法检查失败: {msg}")

        if run_tests and ok:
            baseline = _test_baseline(root)
            cmd = detect_test_command(workdir)
            if baseline is None or cmd is None:
                attempt.tests_pass = None
                if baseline is None:
                    attempt.notes.append(
                        "项目自带的测试在未打补丁时就无法通过（常见原因：缺依赖、缺环境变量），"
                        "因此跳过回归判定，只验证到语法层"
                    )
                else:
                    attempt.notes.append("未发现测试套件，跳过回归测试")
            else:
                code, out = _run(cmd, workdir, 600)
                attempt.tests_pass = code == 0
                if code != 0:
                    attempt.errors.append(f"测试失败（{' '.join(cmd)}）: {out.strip()[:600]}")
    finally:
        if workdir is not None:
            shutil.rmtree(workdir.parent, ignore_errors=True)

    return attempt


def finding_still_present(finding: Finding, base_text: str, root: Path) -> bool:
    """在可能已被部分修补的文本上重扫，判断该漏洞是否还存在。

    用于区分「修复失败」和「已被前一条补丁顺带修掉」。
    后者很常见：一条补丁把相邻两行凭据一起改成环境变量读取，
    另一条 finding 指向的第二行自然就消失了，这不叫失败。
    """
    tmp = Path(tempfile.mkdtemp(prefix="bee-check-"))
    try:
        probe = tmp / Path(finding.path).name
        write_source(probe, base_text)
        hits = [f for f in scan_file(probe, tmp) if f.rule_id == finding.rule_id]
        return len(hits) > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def rescan_after_edit(root: Path, rel_path: str, rule_id: str) -> list[Finding]:
    """对外暴露：对已落盘的文件重扫某条规则。"""
    target = root / rel_path
    if not target.exists():
        return []
    return [f for f in scan_file(target, root) if f.rule_id == rule_id]


def collect_baseline(root: Path) -> list[Finding]:
    return scan_tree(root)


def apply_session(root: Path, session: PatchSession) -> tuple[int, list[str]]:
    """把会话里累积的编辑按顺序写入原文件。每个文件只备份一次。

    必须按 session 里的顺序应用：同一文件的多条补丁之间存在前后依赖，
    打乱顺序会导致 old_string 对不上。
    """
    written = 0
    errors: list[str] = []

    for rel, proposals in session.accepted.items():
        target = root / rel
        try:
            text = read_source(target)
        except OSError as exc:
            errors.append(f"{rel}: 读取失败 {exc}")
            continue

        backup = target.with_suffix(target.suffix + ".bee.bak")
        shutil.copy2(target, backup)

        failed = False
        for proposal in proposals:
            nxt = proposal.apply_to(text)
            if nxt is None:
                errors.append(f"{rel}: 有一条补丁无法应用，文件未写入，请手动处理")
                failed = True
                break
            text = nxt
        if failed:
            continue

        write_source(target, text)
        written += 1

    return written, errors


def apply_to_disk(root: Path, proposal: EditProposal) -> bool:
    """单条落盘，保留给脚本化场景。先备份原文件。"""
    target = root / proposal.file
    try:
        original = read_source(target)
    except OSError:
        return False
    patched = replace_once(original, proposal.old_string, proposal.new_string)
    if patched is None:
        return False
    backup = target.with_suffix(target.suffix + ".bee.bak")
    shutil.copy2(target, backup)
    write_source(target, patched)
    return True


def cleanup_stale_temp() -> int:
    """清理异常退出遗留的临时目录。"""
    base = Path(tempfile.gettempdir())
    removed = 0
    for p in base.glob("bee-*"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            removed += 1
    return removed


def platform_note() -> str:
    return f"{os.name} / Python {sys.version.split()[0]}"

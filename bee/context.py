"""上下文装配：把一条 finding 还原成「可判断的完整证据包」。

可解释性的质量上限由这里决定。只给 LLM 一行代码，它只能写通用套话；
给到完整函数 + 数据来源 + 调用方，它才能说出「哪个变量、从哪进、为什么堵不住」。
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from .io_utils import read_source
from .models import Finding

# 单条 finding 的上下文预算（字符），防止把长文件整段塞进 prompt
MAX_FUNC_CHARS = 6000
MAX_CALLER_CHARS = 2500


def _numbered(source: str, start_line: int, width: int = 5) -> str:
    """给代码加行号前缀。

    没有行号锚点时，模型只能数片段内的相对位置，引用必然偏移。
    实测中它把第 29 行说成第 28 行，还编出一条指向不存在内容的「证据」。
    行号是显式给出的，不是让它猜的。
    """
    lines = source.splitlines()
    return "\n".join(
        f"{start_line + i:>{width}} | {ln}" for i, ln in enumerate(lines)
    )


@dataclass
class CallerSite:
    path: str
    line: int
    snippet: str


@dataclass
class CodeContext:
    """喂给 LLM 的证据包。"""

    path: str
    language: str
    function_name: str = ""
    function_source: str = ""
    function_start: int = 0
    enclosing_class: str = ""
    imports: str = ""
    file_head: str = ""
    hit_line_content: str = ""
    hit_line_start: int = 0
    callers: list[CallerSite] = field(default_factory=list)
    entry_markers: list[str] = field(default_factory=list)
    related_definitions: str = ""

    def to_prompt(self) -> str:
        parts: list[str] = []
        parts.append(f"### 目标文件\n`{self.path}`（{self.language}）")
        parts.append(
            "> 以下代码块左侧的数字是**真实文件行号**，引用时必须使用这些编号，不要自己数。"
        )

        if self.enclosing_class or self.function_name:
            scope = ".".join(filter(None, [self.enclosing_class, self.function_name]))
            parts.append(f"### 漏洞所在函数\n`{scope}` 起始于第 {self.function_start} 行")
        if self.function_source:
            numbered = _numbered(self.function_source, max(self.function_start, 1))
            parts.append(f"```{self.language}\n{numbered}\n```")
        else:
            numbered = _numbered(self.file_head, 1)
            parts.append(f"### 相关代码片段\n```{self.language}\n{numbered}\n```")

        hit = _numbered(self.hit_line_content, max(self.hit_line_start, 1))
        parts.append(f"### 命中位置附近的原始内容\n```\n{hit}\n```")

        if self.imports:
            parts.append(f"### 该文件的 import\n```{self.language}\n{self.imports}\n```")

        if self.entry_markers:
            parts.append("### 疑似外部入口\n" + "\n".join(f"- `{m}`" for m in self.entry_markers))

        if self.callers:
            caller_text = "\n".join(
                f"- `{c.path}:{c.line}`\n```\n{_numbered(c.snippet, max(c.line - 1, 1))}\n```"
                for c in self.callers[:4]
            )
            parts.append(f"### 调用方（判断数据是否真的来自外部）\n{caller_text}")
        else:
            parts.append("### 调用方\n未在此代码库中找到直接调用，可能通过框架路由或反射调用。")

        if self.related_definitions:
            parts.append(f"### 同文件相关定义\n{self.related_definitions}")

        return "\n\n".join(p for p in parts if p and p.strip())

    def line_range(self) -> tuple[int, int]:
        """模型可以安全引用的行号范围。超出即判为幻觉。"""
        lo = self.hit_line_start or self.function_start or 1
        # 函数边界优先：它是最可靠的锚点
        if self.function_source:
            span = self.function_source.count("\n") + 1
            hi = self.function_start + span
            return self.function_start, hi
        span = max(self.hit_line_content.count("\n") + 1, 1)
        return lo, lo + span


# ---------------------------------------------------------------- Python 精确定位


def _python_function_at(source: str, line: int) -> tuple[ast.AST | None, ast.AST | None]:
    """返回 (命中的函数节点, 其所属类节点)。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None, None

    best: ast.AST | None = None
    best_cls: ast.AST | None = None

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        if start <= line <= end:
            # 取最内层（范围最小）的函数
            if best is None or start >= getattr(best, "lineno", 0):
                best = node

    if best is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.lineno <= line <= getattr(node, "end_lineno", node.lineno):
                    if any(b is best for b in ast.walk(node)):
                        best_cls = node
                        break
    return best, best_cls


def _python_imports(source: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    lines: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            seg = ast.get_source_segment(source, node)
            if seg:
                lines.append(seg)
    return "\n".join(lines[:40])


# ---------------------------------------------------------------- 通用启发式

FUNC_START_PATTERNS = [
    r"^\s*(?:async\s+)?def\s+(\w+)",
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)",
    r"^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(?[^=]*=>",
    r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)",
    r"^\s*(?:public|private|protected|static|final|\s)*[\w<>\[\],\s]+\s+(\w+)\s*\([^;]*\)\s*(?:throws[^{]*)?\{",
    r"^\s*(?:public|private|protected)?\s*(?:static\s+)?function\s+(\w+)",
]
CLASS_PATTERNS = [r"^\s*class\s+(\w+)", r"^\s*(?:public\s+)?(?:final\s+)?class\s+(\w+)"]


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def _brace_block(text: str, hit_line: int) -> tuple[int, int]:
    """对花括号语言，从命中行向上找函数签名，向下配对花括号。"""
    lines = text.splitlines()
    idx = min(max(hit_line - 1, 0), len(lines) - 1)
    start = max(0, idx - 60)
    for i in range(idx, start - 1, -1):
        for pat in FUNC_START_PATTERNS:
            if re.match(pat, lines[i]):
                # 向下配对
                depth = 0
                begun = False
                for j in range(i, min(len(lines), i + 400)):
                    depth += lines[j].count("{") - lines[j].count("}")
                    if "{" in lines[j]:
                        begun = True
                    if begun and depth <= 0:
                        return i, j
                return i, min(len(lines) - 1, i + 200)
    return max(0, idx - 12), min(len(lines) - 1, idx + 12)


def _indent_block(text: str, hit_line: int) -> tuple[int, int]:
    """对缩进语言，向上找同级缩进最小的 def，向下按缩进收束。"""
    lines = text.splitlines()
    idx = min(max(hit_line - 1, 0), len(lines) - 1)
    hit_indent = _indent_of(lines[idx])

    start = 0
    for i in range(idx, -1, -1):
        for pat in FUNC_START_PATTERNS:
            if re.match(pat, lines[i]):
                start = i
                break
        else:
            continue
        break

    if start == 0 and not any(re.match(p, lines[0]) for p in FUNC_START_PATTERNS):
        start = max(0, idx - 10)

    base_indent = _indent_of(lines[start])
    end = len(lines) - 1
    for j in range(start + 1, len(lines)):
        if lines[j].strip() and _indent_of(lines[j]) <= base_indent:
            end = j - 1
            break
    if end <= start:
        end = min(len(lines) - 1, start + 30)
    _ = hit_indent
    return start, end


def _func_name(lines: list[str], start: int) -> str:
    for pat in FUNC_START_PATTERNS:
        m = re.match(pat, lines[start])
        if m and m.groups():
            return m.group(1)
    return ""


def _enclosing_class(lines: list[str], start: int) -> str:
    target_indent = _indent_of(lines[start])
    for i in range(start - 1, max(-1, start - 300), -1):
        if _indent_of(lines[i]) < target_indent:
            for pat in CLASS_PATTERNS:
                m = re.match(pat, lines[i])
                if m and m.groups():
                    return m.group(1)
    return ""


def _generic_imports(lines: list[str]) -> str:
    out: list[str] = []
    for line in lines[:120]:
        s = line.strip()
        if re.match(r"^(?:import|from|using|require|#include|const\s+\w+\s*=\s*require)", s):
            out.append(line)
        if len(out) >= 25:
            break
    return "\n".join(out)


# ---------------------------------------------------------------- 数据来源识别

TAINT_SOURCE_PATTERNS = [
    r"request\.(?:args|form|json|values|GET|POST|body|query|params|cookies|headers)",
    r"req\.(?:body|query|params|cookies|headers)",
    r"ctx\.(?:Request|Query|Param|FormValue)",
    r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE",
    r"sys\.argv|process\.argv|os\.environ\.get|input\(",
    r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader)",
    r"r\.URL\.Query\(\)|c\.(?:Param|Query|Bind)",
]

ENTRY_DECORATOR_PATTERNS = [
    r"@app\.(?:route|get|post|put|delete|patch)",
    r"@router\.(?:get|post|put|delete|patch)",
    r"@(?:Get|Post|Put|Delete|Request)Mapping",
    r"\b(?:app|router|r)\.(?:get|post|put|delete|use|all)\s*\(",
]


def _find_entry_markers(text: str) -> list[str]:
    markers: list[str] = []
    for pat in ENTRY_DECORATOR_PATTERNS:
        for m in re.finditer(pat, text):
            line_no = text.count("\n", 0, m.start()) + 1
            line = text.splitlines()[line_no - 1].strip()
            markers.append(f"L{line_no}: {line[:120]}")
            if len(markers) >= 5:
                return markers
    return markers


def _find_taint_sources(text: str) -> list[str]:
    hits: list[str] = []
    lines = text.splitlines()
    for pat in TAINT_SOURCE_PATTERNS:
        for m in re.finditer(pat, text):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1].strip()
            entry = f"L{line_no}: {snippet[:140]}"
            if entry not in hits:
                hits.append(entry)
            if len(hits) >= 6:
                return hits
    return hits


def _find_callers(root: Path, func_name: str, exclude: Path, limit: int = 4) -> list[CallerSite]:
    if not func_name or len(func_name) < 3:
        return []
    callers: list[CallerSite] = []
    try:
        files = [p for p in root.rglob("*") if p.is_file() and p.suffix in
                 {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".php"}
                 and not any(part in {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
                             for part in p.parts)]
    except OSError:
        return []

    pat = re.compile(rf"\b{re.escape(func_name)}\s*\(")
    for f in files:
        if f.resolve() == exclude.resolve():
            continue
        try:
            text = read_source(f)
        except OSError:
            continue
        if func_name not in text:
            continue
        for m in pat.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            lines = text.splitlines()
            snippet = "\n".join(lines[max(0, line_no - 2): line_no + 1])
            # 跳过定义处
            if re.search(r"(?:def|function|func|class)\s+" + re.escape(func_name), snippet):
                continue
            callers.append(CallerSite(str(f.relative_to(root)).replace("\\", "/"), line_no, snippet))
            break
        if len(callers) >= limit:
            break
    return callers


def build_context(finding: Finding, root: Path) -> CodeContext:
    target = root / finding.path
    try:
        text = read_source(target)
    except OSError:
        return CodeContext(path=finding.path, language="", hit_line_content=finding.snippet)

    from .detect import detect_language

    lang = detect_language(target)
    lines = text.splitlines()

    ctx = CodeContext(
        path=finding.path,
        language=lang or "text",
        hit_line_content="\n".join(
            lines[max(0, finding.start_line - 4): finding.end_line + 3]
        )[:2000],
        hit_line_start=max(1, finding.start_line - 4),
        entry_markers=_find_entry_markers(text) or _find_taint_sources(text),
    )

    if lang == "python":
        node, cls = _python_function_at(text, finding.start_line)
        ctx.imports = _python_imports(text)
        if node is not None:
            start = getattr(node, "lineno", 1)
            end = getattr(node, "end_lineno", start)
            ctx.function_name = getattr(node, "name", "")
            ctx.function_start = start
            ctx.enclosing_class = getattr(cls, "name", "") if cls is not None else ""
            seg = "\n".join(lines[start - 1: min(end, len(lines))])
            ctx.function_source = seg[:MAX_FUNC_CHARS]
        else:
            ctx.file_head = text[:MAX_FUNC_CHARS]
    else:
        ctx.imports = _generic_imports(lines)
        if lang in {"javascript", "typescript", "go", "java", "php", "c", "cpp"}:
            start, end = _brace_block(text, finding.start_line)
        else:
            start, end = _indent_block(text, finding.start_line)
        ctx.function_start = start + 1
        ctx.function_name = _func_name(lines, start)
        ctx.enclosing_class = _enclosing_class(lines, start)
        seg = "\n".join(lines[start: end + 1])
        if seg.strip():
            ctx.function_source = seg[:MAX_FUNC_CHARS]
        else:
            ctx.file_head = text[:MAX_FUNC_CHARS]

    ctx.callers = _find_callers(root, ctx.function_name, target)

    # 同文件中与漏洞规则相关的其他敏感调用，帮助 LLM 判断是否同类问题成片存在
    related = []
    for m in re.finditer(r"(?im)^\s*(?:def|function|func|class)\s+(\w+)[^\n]*", text):
        name = m.group(1)
        if name and name != ctx.function_name:
            related.append(name)
        if len(related) >= 12:
            break
    if related:
        ctx.related_definitions = "同文件还定义了：" + "、".join(related)

    return ctx

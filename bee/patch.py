"""补丁生成：让模型改代码，并且改错了能自己修。

核心机制是「失败回灌」——把机器验证的具体失败原因（old_string 找不到、
重扫仍命中、语法错误、测试断言失败）原样喂回模型重试。
只做单轮生成的工具实际可用率很低，因为 LLM 在空白、缩进、上下文匹配上
出错是常态，而这些错误几乎都能通过一次带反馈的重试修掉。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .context import CodeContext
from .io_utils import read_source
from .llm import LLMClient, LLMError
from .models import Explanation, Finding, PatchAttempt
from .verify import EditProposal, FileEdit, PatchSession, replace_once, verify_patch

PATCH_SYSTEM = """你是负责修漏洞的工程师。你的补丁会经过机器验证，验不过就打回重来。

硬性约束，违反任何一条都会被自动拒绝：
1. old_string 必须从原始文件里逐字复制，包括所有空格和缩进。它必须在文件中唯一出现。
2. 代码上下文里的行号前缀（形如 `   29 | `）是展示用的，**不属于文件内容**。
   old_string 和 new_string 都必须去掉这层前缀，只写真实代码。
3. new_string 保持原有的缩进风格、命名风格、代码风格。不要顺手重构、不要改注释格式、不要调整无关行的空白。
4. 只改与这个漏洞直接相关的部分。改动行数越少越好。
5. 不引入新依赖。如果安全做法需要新库，改用标准库方案或现有依赖。
6. 不改变函数的公开签名和返回结构，除非漏洞本身就出在契约里。
7. 不要在模块顶层引入「import 时就抛异常」的代码。环境变量读取必须容忍缺失
   （给默认值、返回 None、或延迟到函数内部再读）。把模块级常量改成
   os.environ["X"] 会让整个模块无法 import，测试和调用方全部崩掉——这是最常见的误修。
8. 绝对不许修改测试文件（test_*、*_test.py、tests/ 目录）、CI 配置（.github/）、
   构建配置（package.json、pyproject.toml、go.mod、Makefile）。
   改测试让它变绿是作弊，这类补丁会被直接拒绝，且浪费一轮重试。
   如果测试因为这个漏洞本身需要调整，在 side_effects 里说明，不要自己动手改。
9. 如果漏洞必须跨文件才能修好，可以在 edit 里指定 "file" 来改调用方，
   但不能借此修改上述受保护文件。

返回严格 JSON，不加 markdown 围栏：
{
  "file": "相对路径，与输入一致",
  "edits": [
    {"old_string": "原文件中的精确片段", "new_string": "替换后的片段"}
  ],
  "rationale": "这个改动改变了什么语义边界，为什么能堵住攻击路径",
  "side_effects": "可能的副作用或需要同步修改的地方；没有就写「无」"
}

关于 edits：
- 按数组顺序应用，通常只需要一条。
- 当修复需要新增 import（例如改用 io.BytesIO、subprocess.run、secrets.token_hex）时，
  必须再加一条 edit 改导入区，否则新名字未定义，代码会 NameError。
  这种两处修改的场景很常见，不要试图把 import 和函数体塞进同一个 old_string。
- 当修复必然牵动调用方（改了函数签名、改了参数个数、改了返回结构），
  在对应 edit 里写 "file": "调用方相对路径" 即可跨文件修改。
  宁可多改一个文件把调用方同步掉，也不要留下半套修复——那比不修更危险。
  每个 edit 的 file 都相对于项目根目录，缺省沿用顶层 file。"""


def _patch_prompt(
    finding: Finding,
    expl: Explanation,
    ctx: CodeContext,
    prev: PatchAttempt | None,
) -> str:
    body = f"""请修复下面这个已确认的漏洞。

## 漏洞
- 位置：`{finding.location}`
- 类型：{finding.message}
- CWE：{', '.join(finding.cwe) or '未标注'}
- 严重级别：{finding.severity.value}

## 已确认的根因
{expl.root_cause}

## 已确认的攻击路径
{expl.attack_path}

## 修复目标
{expl.fix_rationale}

## 代码上下文
{ctx.to_prompt()}
"""
    if prev is not None:
        body += f"""
## 上一轮补丁未通过验证，必须修正

失败原因：{prev.failure_reason()}

上一轮的改动：
```diff
{prev.diff[:2500]}
```

重新给补丁时注意：
- 「old_string 找不到或不唯一」→ 从上面的代码上下文里重新复制一段更短但唯一的片段。
- 「重扫仍命中」→ 改动没有真正消除危险模式，要从根因上改（例如改成参数化查询，而不是只转义引号）。
- 「语法错误」→ 检查括号、缩进、语句完整性。
- 「测试失败」→ 改动破坏了既有行为契约。特别注意：如果报错是 ImportError / 模块导入失败，
  说明你在模块顶层引入了需要外部条件的代码（最常见是 os.environ["X"]），
  改成用 os.environ.get("X", 默认值) 或在函数内部读取。
"""
    return body


def _extract_json(raw: str) -> dict:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    if not text.startswith("{"):
        i = text.find("{")
        if i >= 0:
            text = text[i:]
    j = text.rfind("}")
    if j >= 0:
        text = text[: j + 1]
    return json.loads(text)


def _locate_ignoring_indent(file_text: str, old: str) -> str | None:
    """精确匹配失败时，按「忽略首尾空白」重新定位原片段。

    专治模型最常见的错误：缩进写错两格，或多了一个空行。
    定位到行区间后用文件里的真实内容替换 old_string，保证能落地。
    只在匹配唯一时返回，避免改错地方。
    """
    old_lines = [ln.strip() for ln in old.splitlines() if ln.strip()]
    if not old_lines:
        return None
    file_lines = file_text.splitlines()
    span = len(old_lines)

    hits: list[int] = []
    for start in range(len(file_lines) - span + 1):
        if all(file_lines[start + i].strip() == old_lines[i] for i in range(span)):
            hits.append(start)
            if len(hits) > 1:
                return None  # 不唯一，拒绝
    if not hits:
        return None
    start = hits[0]
    return "\n".join(file_lines[start: start + span])


def _shift_indent(new: str, delta: int) -> str:
    if delta == 0:
        return new
    out: list[str] = []
    for ln in new.splitlines():
        if not ln.strip():
            out.append(ln)
        elif delta > 0:
            out.append(" " * delta + ln)
        else:
            cut = min(-delta, len(ln) - len(ln.lstrip()))
            out.append(ln[cut:])
    return "\n".join(out)


def _indent_delta(old: str, new: str) -> int:
    old_first = next((ln for ln in old.splitlines() if ln.strip()), "")
    new_first = next((ln for ln in new.splitlines() if ln.strip()), "")

    def ind(s: str) -> int:
        return len(s) - len(s.lstrip())

    return ind(new_first) - ind(old_first)


LINE_NUM_PREFIX = re.compile(r"^\s*\d+\s*\|\s?", re.M)


def _strip_line_numbers(text: str) -> str:
    """剥掉上下文展示用的行号前缀。

    给 prompt 加行号锚点是必须的（否则模型引用位置必然偏移），
    副作用是模型偶尔会把 `   29 | ` 连同代码一起抄进 old_string。
    这里做一层容错，而不是让一次可恢复的错误浪费一整轮。
    """
    return LINE_NUM_PREFIX.sub("", text)


def _fix_pair(text: str, old: str, new: str) -> tuple[str, str]:
    """把一条编辑的 old/new 修正到能落地的形态。

    依次尝试：原样 → 剥行号前缀 → 忽略缩进重新定位。
    """
    if not old or text.count(old) == 1:
        return old, new

    cleaned = _strip_line_numbers(old)
    if cleaned != old and text.count(cleaned) == 1:
        return cleaned, _strip_line_numbers(new)

    fixed = _locate_ignoring_indent(text, old)
    if fixed:
        return fixed, _shift_indent(new, _indent_delta(old, fixed))

    return old, new


def _declared_files(data: dict, finding: Finding) -> list[str]:
    """先从模型输出里解析出涉及哪些文件，好提前取出累积文本。"""
    default = str(data.get("file") or finding.path)
    out = [default]
    raw_edits = data.get("edits")
    if isinstance(raw_edits, list):
        for item in raw_edits:
            if not isinstance(item, dict):
                continue
            rel = str(item.get("file") or default)
            if rel not in out:
                out.append(rel)
    return out


def _build_proposal(
    data: dict,
    finding: Finding,
    root: Path,
    base_texts: dict[str, str] | None = None,
) -> EditProposal:
    default_file = str(data.get("file") or finding.path)

    file_edits: list[FileEdit] = []
    raw_edits = data.get("edits")
    if isinstance(raw_edits, list):
        for item in raw_edits:
            if not isinstance(item, dict):
                continue
            old = str(item.get("old_string") or "")
            new_value = item.get("new_string")
            if old and new_value is not None:
                file_edits.append(FileEdit(str(item.get("file") or default_file), old, str(new_value)))
    # 兼容只返回单条 old/new 的模型
    if not file_edits and data.get("old_string"):
        file_edits = [FileEdit(default_file, str(data["old_string"]), str(data.get("new_string") or ""))]

    proposal = EditProposal(file=default_file, edits=file_edits)
    proposal.rationale = str(data.get("rationale") or "")
    side = str(data.get("side_effects") or "").strip()
    if side and side not in {"无", "none", "None", "N/A"}:
        proposal.rationale += f"\n\n副作用说明：{side}"

    # 取每个文件的当前内容（可能已含前面补丁的改动）
    current: dict[str, str] = {}
    for edit in file_edits:
        if edit.file in current:
            continue
        if base_texts and edit.file in base_texts:
            current[edit.file] = base_texts[edit.file]
            continue
        try:
            current[edit.file] = read_source(root / edit.file)
        except OSError:
            current[edit.file] = ""

    # 逐条修正，并让后续编辑基于已应用的状态判断唯一性
    fixed: list[FileEdit] = []
    for edit in file_edits:
        text = current.get(edit.file, "")
        actual_old, actual_new = _fix_pair(text, edit.old_string, edit.new_string)
        fixed.append(FileEdit(edit.file, actual_old, actual_new))
        nxt = replace_once(text, actual_old, actual_new)
        if nxt is not None:
            current[edit.file] = nxt

    proposal.edits = fixed
    return proposal


def repair_finding(
    finding: Finding,
    expl: Explanation,
    ctx: CodeContext,
    client: LLMClient | None,
    root: Path,
    *,
    max_rounds: int = 3,
    run_tests: bool = True,
    session: PatchSession | None = None,
) -> list[PatchAttempt]:
    """多轮修复，直到验证通过或用尽轮次。

    传入 session 时，验证基于该文件已累积的编辑，而不是磁盘原文——
    这样同一文件的第二个漏洞不会因为第一个补丁改动过同一片代码而失败。
    """
    if client is None or not client.config.usable:
        return []

    attempts: list[PatchAttempt] = []
    prev: PatchAttempt | None = None

    for round_no in range(1, max_rounds + 1):
        messages = [
            {"role": "system", "content": PATCH_SYSTEM},
            {"role": "user", "content": _patch_prompt(finding, expl, ctx, prev)},
        ]
        try:
            raw = client.chat(messages, json_mode=True, temperature=0.05)
            data = _extract_json(raw)
        except (LLMError, json.JSONDecodeError, ValueError) as exc:
            attempt = PatchAttempt(
                round=round_no, diff="",
                errors=[f"模型输出无法解析: {str(exc)[:200]}"],
            )
            attempts.append(attempt)
            prev = attempt
            continue

        base_texts = None
        if session is not None:
            base_texts = session.base_texts(_declared_files(data, finding))
        proposal = _build_proposal(data, finding, root, base_texts=base_texts)
        attempt = verify_patch(
            finding, proposal, root, round_no,
            run_tests=run_tests, base_texts=base_texts,
        )
        attempt.explanation = proposal.rationale
        attempts.append(attempt)

        if attempt.succeeded:
            if session is not None:
                session.commit(proposal)
            break
        prev = attempt

    return attempts

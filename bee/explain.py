"""可解释性分析：把 finding 变成能被人 review 的论证。

四段式不是格式偏好，是四个必须回答的问题：
  根因 —— 哪一行、哪个变量、哪个假设不成立（不知道这个，补丁是猜的）
  攻击路径 —— 从哪个入口进、怎么走到这里、前置条件是什么（不知道这个，只能修表象）
  影响面 —— 具体泄露什么、能做什么（不知道这个，排不出优先级）
  修复原理 —— 这个改动改变了什么语义（不知道这个，无法 review，也无法说服别人）

反幻觉机制：每条证据必须带行号，行号必须真实存在于文件中，否则要求模型重写。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .context import CodeContext
from .io_utils import read_source
from .llm import LLMClient, LLMError
from .models import Explanation, Finding

SYSTEM_PROMPT = """你是一名做代码审计十几年的安全工程师，正在给开发团队写漏洞报告。

写作要求，违反任何一条都算不合格：
1. 必须指名道姓。说「第 42 行的 uid 参数被格式化进 SQL 文本」，不要说「用户输入未经过滤」。
2. 禁止背诵 CWE/OWASP 的定义。读者知道 SQL 注入是什么，他们要的是这段代码为什么中招。
3. 禁止「可能」「建议」「注意」这类没有信息量的措辞。要么是事实，要么不说。
4. 每条结论都要能指回具体代码位置。
5. 中文写作，技术名词保留英文原文。

四个字段的硬要求：
- root_cause：指出具体的变量名/函数名/行号，解释哪个安全假设在这里不成立。
- attack_path：写出攻击者的完整路径——从哪个入口参数进来，经过哪些函数，最后到达哪个危险操作，需要什么前置条件（是否需登录、是否需特定配置）。
- impact：结合实际业务对象说明后果（能读到哪张表、能执行什么命令、能拿到什么权限），不要写「可能导致数据泄露」这种空话。
- fix_rationale：说明修复改变了什么语义边界，为什么这样就堵住了，以及这个改法是否有副作用或性能代价。

另外输出 evidence 数组：每条一句话，格式为「L行号: 该行证明的结论」。最多 6 条。
代码块左侧的数字是真实文件行号，引用时只能用这些编号，不要自己数行。
不要引用没有提供给你的文件里的内容——那会被判为编造并退回重写。
如果代码证据不足以支撑某个判断，就在该字段里直接写明「证据不足」并说明缺什么，不要编造。"""


def _user_prompt(finding: Finding, ctx: CodeContext, prev_failure: str = "") -> str:
    meta = json.dumps(
        {
            "rule": finding.rule_id,
            "rule_title": finding.message,
            "cwe": finding.cwe,
            "severity": finding.severity.value,
            "location": finding.location,
            "detector_prior_root_cause": finding.raw.get("root_cause_hint", ""),
            "detector_prior_fix": finding.raw.get("fix_hint", ""),
            "matched_text": finding.raw.get("matched", ""),
        },
        ensure_ascii=False,
        indent=2,
    )

    body = f"""请分析下面这个漏洞。

## 检测信号
```json
{meta}
```

## 代码上下文
{ctx.to_prompt()}

## 输出格式
严格返回 JSON，不要加 markdown 代码块：
{{
  "root_cause": "...",
  "attack_path": "...",
  "impact": "...",
  "fix_rationale": "...",
  "confidence": 0.0 到 1.0 之间的数字，表示这个漏洞真实存在的把握,
  "evidence": ["L12: ...", "L45: ..."]
}}

confidence 要诚实。如果证据表明这是误报（比如上游其实做了校验），就把 confidence 打到 0.2 以下，并在 root_cause 里说明为什么这是误报。"""

    if prev_failure:
        body += f"\n\n## 上一次输出不合格，原因如下，请修正后重新输出\n{prev_failure}"
    return body


def _parse_json(raw: str) -> dict:
    text = raw.strip()
    # 容错：剥掉模型偶尔加的代码块围栏
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    if not text.startswith("{"):
        brace = text.find("{")
        if brace >= 0:
            text = text[brace:]
    last = text.rfind("}")
    if last >= 0:
        text = text[: last + 1]
    return json.loads(text)


_EVIDENCE_RE = re.compile(r"^\s*L(\d+)\s*[:：]\s*\S+")


def _import_region_end(source_lines: list[str]) -> int:
    """模块顶部 import 区的结束行号。

    修复经常要动 import（补 io/subprocess），所以证据允许指向 import 区，
    但不能借此放开到整个文件——那等于没有距离约束。
    """
    end = 0
    for idx, line in enumerate(source_lines[:200], 1):
        stripped = line.strip()
        if re.match(r"(?:def|class|async\s+def)\s", stripped):
            break
        if stripped.startswith(("import ", "from ")):
            end = idx
    return end


def _shown_line_numbers(ctx: CodeContext) -> set[int]:
    """从装配好的 prompt 里抽出所有真实出现过的行号。

    校验的语义是「只能引用提供给你的代码」——prompt 的每个代码块都带
    `_numbered` 行号前缀（含跨文件调用方各自的行号），所以这里抽出的集合
    就是允许引用的全集。比「函数范围」更准：related_definitions、调用方
    片段里的行同样是合法证据，而从未展示过的行号一律是编造。
    """
    try:
        prompt = ctx.to_prompt()
    except Exception:
        return set()
    return {int(x) for x in re.findall(r"^\s*(\d+)\s*\|", prompt, re.M)}


def _validate(
    expl: Explanation,
    finding: Finding,
    source_lines: list[str],
    ctx: CodeContext,
) -> list[str]:
    problems: list[str] = []
    missing = expl.missing_fields()
    if missing:
        problems.append("以下字段内容过短或缺失：" + "、".join(missing))
    if not expl.evidence:
        problems.append("evidence 为空，必须给出指向具体行号的证据")

    lo, hi = ctx.line_range()
    import_end = _import_region_end(source_lines)
    shown = _shown_line_numbers(ctx)
    caller_lines = {c.line for c in (getattr(ctx, "callers", None) or [])}
    malformed: list[str] = []
    fake: list[str] = []
    for item in expl.evidence:
        m = _EVIDENCE_RE.match(item)
        if not m:
            # 不匹配「L行号: 结论」的一律判不合格。以前这里是 continue 静默放过，
            # 等于 evidence=["我编的"] 也能通过，反幻觉机制形同虚设。
            malformed.append(item)
            continue
        line_no = int(m.group(1))
        in_caller = any(abs(line_no - cl) <= 1 for cl in caller_lines)

        if shown:
            # 主路径：行号必须真的出现在提供给模型的代码里
            if line_no not in shown:
                fake.append(f"{item}（该行号未出现在提供的代码中）")
                continue
        else:
            # 兜底（上下文未编号时）：函数范围 + import 区 + 已登记调用方
            in_function = lo - 1 <= line_no <= hi + 1
            in_imports = import_end > 0 and line_no <= import_end
            if not (in_function or in_imports or in_caller):
                fake.append(
                    f"{item}（不在漏洞函数 L{lo}-L{hi}、import 区或已识别的调用方行内）"
                )
                continue

        # 引用目标文件本身的行时，还要求该行非空（空行不能支撑任何结论）
        if 1 <= line_no <= len(source_lines) and not in_caller:
            if not source_lines[line_no - 1].strip():
                fake.append(f"{item}（该行是空行，不能作为证据）")

    if malformed:
        problems.append(
            "以下证据不符合「L行号: 结论」格式，必须重写为带真实行号的形式："
            + "；".join(malformed[:3])
        )
    if fake:
        problems.append(
            "以下证据的行号无效（须引用提供给你的代码里的非空行）："
            + "；".join(fake[:3])
        )

    return problems


def _fallback_explanation(finding: Finding) -> Explanation:
    """无 LLM 时的降级解释：用规则自带的先验知识拼出可读结论。

    诚实标注这是规则先验，不是针对本段代码的推理。
    """
    root_hint = finding.raw.get("root_cause_hint", "") or finding.message
    fix_hint = finding.raw.get("fix_hint", "") or "见规则对应的修复建议。"
    return Explanation(
        root_cause=f"{root_hint}（依据规则 {finding.rule_id} 在 {finding.location} 的模式匹配，"
                   f"尚未结合完整代码做人工确认）",
        attack_path="需结合入口参数与调用链确认。当前为规则先验，未做数据流追踪。",
        impact=f"等级判定为 {finding.severity.value}，CWE {', '.join(finding.cwe) or '未标注'}。"
               f"实际影响面需人工复核。",
        fix_rationale=fix_hint,
        confidence=0.4,
        evidence=[f"L{finding.start_line}: 命中规则 {finding.rule_id}"],
    )


def explain(
    finding: Finding,
    ctx: CodeContext,
    client: LLMClient | None,
    root: Path,
    max_rounds: int = 2,
) -> Explanation:
    if client is None or not client.config.usable:
        return _fallback_explanation(finding)

    try:
        lines = read_source(root / finding.path).splitlines()
    except OSError:
        lines = []

    failure = ""
    best: Explanation | None = None

    for _ in range(max_rounds):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _user_prompt(finding, ctx, failure)},
        ]
        try:
            raw = client.chat(messages, json_mode=True)
        except LLMError as exc:
            if best is not None:
                break
            return _fallback_explanation_with_error(finding, str(exc))

        try:
            data = _parse_json(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            failure = f"返回内容不是合法 JSON（{exc}）。请只输出 JSON 对象。"
            continue

        try:
            confidence = float(data.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            # 模型偶尔返回 "high" 这类文本，不能因为一个字段就把整条分析炸掉
            confidence = 0.0
        raw_evidence = data.get("evidence")
        if isinstance(raw_evidence, list):
            evidence = [str(x) for x in raw_evidence][:6]
        elif isinstance(raw_evidence, str) and raw_evidence.strip():
            evidence = [raw_evidence.strip()]
        else:
            # 不是列表/字符串时给空，让 _validate 判不合格，而不是把字符串拆成单字符
            evidence = []

        expl = Explanation(
            root_cause=str(data.get("root_cause", "")).strip(),
            attack_path=str(data.get("attack_path", "")).strip(),
            impact=str(data.get("impact", "")).strip(),
            fix_rationale=str(data.get("fix_rationale", "")).strip(),
            confidence=confidence,
            evidence=evidence,
        )
        problems = _validate(expl, finding, lines, ctx)
        if not problems:
            return expl
        best = expl
        failure = "；".join(problems)

    if best is not None:
        # 两轮仍不合格：结果可以进报告，但必须标记降级，
        # 由调用方决定不再把它当「已确认根因」喂给补丁生成。
        best.degraded = True
        best.degrade_reason = failure or "证据校验未通过"
        return best
    return _fallback_explanation(finding)


def _fallback_explanation_with_error(finding: Finding, error: str) -> Explanation:
    expl = _fallback_explanation(finding)
    expl.root_cause += f"\n\n（LLM 分析失败，已降级为规则先验：{error[:200]}）"
    expl.degraded = True
    expl.degrade_reason = f"LLM 分析失败：{error[:120]}"
    return expl

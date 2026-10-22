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

    # 行号范围校验：模型只能引用实际提供给它的那段代码
    lo, hi = ctx.line_range()
    fake: list[str] = []
    for item in expl.evidence:
        m = re.match(r"\s*L(\d+)", item)
        if not m:
            continue
        line_no = int(m.group(1))
        if not (1 <= line_no <= max(1, len(source_lines))):
            fake.append(item)
        elif not (lo - 1 <= line_no <= hi + 1):
            fake.append(item)
    if fake:
        problems.append(
            f"以下证据引用的行号不在提供的代码范围 L{lo}-L{hi} 内，属于编造："
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

        expl = Explanation(
            root_cause=str(data.get("root_cause", "")).strip(),
            attack_path=str(data.get("attack_path", "")).strip(),
            impact=str(data.get("impact", "")).strip(),
            fix_rationale=str(data.get("fix_rationale", "")).strip(),
            confidence=float(data.get("confidence", 0) or 0),
            evidence=[str(x) for x in (data.get("evidence") or [])][:6],
        )
        problems = _validate(expl, finding, lines, ctx)
        if not problems:
            return expl
        best = expl
        failure = "；".join(problems)

    return best or _fallback_explanation(finding)


def _fallback_explanation_with_error(finding: Finding, error: str) -> Explanation:
    expl = _fallback_explanation(finding)
    expl.root_cause += f"\n\n（LLM 分析失败，已降级为规则先验：{error[:200]}）"
    return expl

"""报告渲染：把修复结果变成可以直接贴进评审单的 Markdown。"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from .models import RepairResult, Severity

SEV_BADGE = {
    Severity.ERROR: "🔴 高危",
    Severity.WARNING: "🟠 中危",
    Severity.INFO: "🔵 提示",
}


def _summary(results: list[RepairResult], scanned_files: int) -> str:
    total = len(results)
    if total == 0:
        return "## 概览\n\n未发现问题。\n"

    by_sev = Counter(r.finding.severity for r in results)
    verified = sum(1 for r in results if r.status == "verified")
    covered = sum(1 for r in results if r.status == "covered")
    explained = sum(1 for r in results if r.explanation is not None)
    attempt_total = sum(len(r.attempts) for r in results)

    rows = [
        ("扫描文件", f"{scanned_files}"),
        ("发现问题", f"{total}"),
        ("高危", f"{by_sev.get(Severity.ERROR, 0)}"),
        ("中危", f"{by_sev.get(Severity.WARNING, 0)}"),
        ("提示", f"{by_sev.get(Severity.INFO, 0)}"),
        ("已生成解释", f"{explained}"),
        ("补丁通过机器验证", f"{verified}"),
        ("已被前述补丁覆盖", f"{covered}"),
        ("补丁尝试轮次合计", f"{attempt_total}"),
    ]

    lines = ["## 概览", "", "| 项 | 值 |", "| --- | --- |"]
    lines += [f"| {k} | {v} |" for k, v in rows]
    return "\n".join(lines) + "\n"


def _status_line(result: RepairResult) -> str:
    if result.status == "verified":
        a = result.accepted
        assert a is not None
        bits = ["补丁已应用", "漏洞消失" if a.finding_gone else "漏洞仍在"]
        bits.append("语法通过" if a.compiles else "语法失败")
        if a.tests_pass is True:
            bits.append("测试通过")
        elif a.tests_pass is False:
            bits.append("测试失败")
        elif any("基线" in n or "已失败" in n for n in a.notes):
            # 红基线/环境不可用与「没有测试」是两件事，不能都写成「无测试可跑」
            bits.append("回归信号不可用（项目测试本就无法通过）")
        else:
            bits.append("无测试可跑")
        return f"✅ **已验证修复**（第 {a.round} 轮）— " + " · ".join(bits)
    if result.status == "covered":
        return "⊘ **已被前述补丁覆盖** — 该处在之前的修复中一并消除，无需单独改"
    if result.status == "unverified":
        last = result.attempts[-1]
        return f"⚠️ **未通过验证**（{len(result.attempts)} 轮尝试）— {last.failure_reason()}"
    return "ℹ️ 仅解释，未生成补丁"


def render_finding(index: int, result: RepairResult) -> str:
    f = result.finding
    e = result.explanation

    lines = [
        f"### {index}. {f.message}",
        "",
        f"- **位置**：`{f.location}`",
        f"- **级别**：{SEV_BADGE.get(f.severity, f.severity.value)}",
        f"- **CWE**：{', '.join(f.cwe) or '未标注'}　**OWASP**：{', '.join(f.owasp) or '未标注'}",
        f"- **规则**：`{f.rule_id}`",
        f"- **状态**：{_status_line(result)}",
        "",
    ]

    if e is not None:
        conf = f"{e.confidence:.0%}" if e.confidence else "未评估"
        if e.degraded:
            lines += [
                "> ⚠️ **解释已降级**：多轮校验后证据仍未通过行号/格式校验，"
                "以下内容**不可作为已确认根因使用**，本次未据此生成补丁。",
                "",
                f"> 降级原因：{e.degrade_reason or '证据校验未通过'}",
                "",
            ]
        lines += [
            "#### 根因",
            "",
            e.root_cause or "（未生成）",
            "",
            "#### 攻击路径",
            "",
            e.attack_path or "（未生成）",
            "",
            "#### 影响面",
            "",
            e.impact or "（未生成）",
            "",
            "#### 修复原理",
            "",
            e.fix_rationale or "（未生成）",
            "",
        ]
        if e.evidence:
            lines += ["#### 证据", ""]
            lines += [f"- {item}" for item in e.evidence]
            lines.append("")
        lines.append(f"*模型置信度：{conf}*")
        lines.append("")

    if result.accepted is not None:
        lines += [
            "#### 补丁（已通过机器验证，待人工 review）",
            "",
            "```diff",
            result.accepted.diff.strip(),
            "```",
            "",
        ]
        if result.accepted.notes:
            lines += ["**验证备注**："] + [f"- {n}" for n in result.accepted.notes] + [""]
    elif result.attempts:
        lines += ["#### 未通过的补丁尝试", ""]
        for a in result.attempts:
            lines.append(f"**第 {a.round} 轮**：{a.failure_reason() or '未知原因'}")
            if a.diff.strip():
                lines += ["", "```diff", a.diff.strip()[:1800], "```", ""]
        lines.append("")

    lines.append("<details><summary>命中代码</summary>")
    lines += ["", "```", f.snippet, "```", "", "</details>", ""]
    return "\n".join(lines)


def render_report(
    results: list[RepairResult],
    root: Path,
    scanned_files: int,
    *,
    include_drafts: bool = True,
    display_path: str | None = None,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    # 报告会被贴进评审单、工单、甚至公开仓库，不该带出别人的本机目录结构
    shown = display_path or root.name
    head = [
        "# 漏洞审计与可解释性修复报告",
        "",
        f"- 目标：`{shown}`",
        f"- 生成时间：{now}",
        f"- 工具：bee（规则引擎 + LLM 四段式解释 + 机器验证补丁）",
        "",
        "> 所有补丁均在临时副本上验证，未改动原仓库。落盘需人工确认。",
        "",
    ]

    body = [_summary(results, scanned_files), ""]

    verified = [r for r in results if r.status == "verified"]
    covered = [r for r in results if r.status == "covered"]
    unverified = [r for r in results if r.status == "unverified"]
    explained_only = [r for r in results if r.status == "explained"]

    if verified:
        body += ["## 已验证修复", ""]
        body += [render_finding(i, r) for i, r in enumerate(verified, 1)]
    if covered:
        body += ["## 已被前述补丁覆盖", ""]
        body += [render_finding(i, r) for i, r in enumerate(covered, 1)]
    if unverified and include_drafts:
        body += ["## 未通过验证（需人工介入）", ""]
        body += [render_finding(i, r) for i, r in enumerate(unverified, 1)]
    if explained_only and include_drafts:
        body += ["## 仅解释（未生成补丁）", ""]
        body += [render_finding(i, r) for i, r in enumerate(explained_only, 1)]

    if results:
        body += [
            "## 后续动作",
            "",
            "- [ ] 逐条 review「已验证修复」的补丁，确认没有改变业务语义",
            "- [ ] 「未通过验证」的条目需要人工判断：是模型修法不对，还是检测本身是误报",
            "- [ ] 对同类问题做全局检索，避免只修了命中的那一处",
            "",
        ]

    return "\n".join(head + body)


def write_report(content: str, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return output


def render_console(results: list[RepairResult]) -> str:
    """终端简报。"""
    if not results:
        return "未发现问题。"

    lines: list[str] = []
    for r in results:
        f = r.finding
        icon = {"verified": "✅", "unverified": "⚠️", "covered": "⊘", "explained": "·"}[r.status]
        sev = {"ERROR": "HIGH", "WARNING": "MED", "INFO": "LOW"}[f.severity.value]
        lines.append(f"{icon} [{sev}] {f.location}  {f.message}")
    verified = sum(1 for r in results if r.status == "verified")
    unverified = sum(1 for r in results if r.status == "unverified")
    covered = sum(1 for r in results if r.status == "covered")
    lines.append("")
    lines.append(
        f"合计 {len(results)} 条：已验证修复 {verified}，已被覆盖 {covered}，"
        f"未通过验证 {unverified}，仅解释 {len(results) - verified - unverified - covered}"
    )
    return "\n".join(lines)

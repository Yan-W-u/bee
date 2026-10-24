"""命令行入口：scan 只看，audit 解释，fix 出补丁并验证。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, baseline, sarif
from .detect import (
    BUILTIN_RULES, iter_source_files, load_custom_rules, matches_globs,
    merge_findings, scan_tree,
)
from .explain import explain
from .llm import LLMClient, LLMConfig
from .models import Finding, RepairResult, Severity
from .patch import repair_finding
from .report import render_console, render_report, write_report
from .verify import PatchSession, apply_session, cleanup_stale_temp, finding_still_present

SEV_ORDER = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}


def _finding_dict(f: Finding) -> dict:
    payload = {
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "message": f.message,
        "path": f.path,
        "start_line": f.start_line,
        "end_line": f.end_line,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "references": f.references,
        "detector": f.detector,
        "fingerprint": f.fingerprint,
        "code_line": f.code_line,
        "snippet": f.snippet,
    }
    if f.trace:
        payload["trace"] = [
            {"label": t.label, "path": t.path, "line": t.line, "content": t.content}
            for t in f.trace
        ]
    return payload


def _progress(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _select_rules(ids: list[str] | None, custom: Path | None) -> list:
    rules = list(BUILTIN_RULES)
    if custom:
        rules = load_custom_rules(custom)
    if ids:
        wanted = {i.strip() for i in ids if i.strip()}
        rules = [r for r in rules if r.id in wanted or r.id.split(".")[-1] in wanted]
    return rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bee",
        description="漏洞检测 + 可解释性修复 + 机器验证",
    )
    sub = p.add_subparsers(dest="command")

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("target", help="要审计的项目目录或单个文件")
        sp.add_argument("--output", "-o", help="报告输出路径（.md）")
        sp.add_argument("--json", action="store_true", help="以 JSON 输出结果")
        sp.add_argument("--min-severity", choices=["info", "warning", "error"], default="info")
        sp.add_argument("--rule", action="append", help="只跑指定规则（可多次）")
        sp.add_argument("--rules-file", type=Path, help="自定义规则文件（Python，定义 RULES 列表）")
        sp.add_argument("--include", action="append", help="只扫描匹配的 glob，如 'src/**/*.py'")
        sp.add_argument("--exclude", action="append", default=[], help="排除匹配的 glob")
        sp.add_argument("--limit", type=int, default=0, help="最多处理 N 条发现")
        sp.add_argument("--detector", choices=["auto", "rules", "semgrep", "both"], default="auto",
                        help="检测后端：rules=内置规则，semgrep=外部引擎，both=合并，auto=有 semgrep 就合并")
        sp.add_argument("--semgrep-config", default="auto",
                        help="semgrep 规则集，默认 auto（registry），也可传本地规则目录")
        sp.add_argument("--baseline", type=Path, help="只报告相对该基线新增的问题")
        sp.add_argument("--write-baseline", type=Path, help="把当前结果写成基线文件")
        sp.add_argument("--fail-on-new", action="store_true",
                        help="存在基线之外的新问题时以退出码 1 结束（供 CI 使用）")
        sp.add_argument("--fail-on-findings", action="store_true",
                        help="只要还有未修复/未入基线的发现就以退出码 1 结束（CI 门禁）")
        sp.add_argument("--sarif", type=Path, help="额外输出 SARIF 2.1.0 供 GitHub Code Scanning 使用")
        sp.add_argument("--llm-base-url", default=None)
        sp.add_argument("--llm-key", default=None)
        sp.add_argument("--llm-model", default=None)
        sp.add_argument("--no-llm", action="store_true", help="不调用模型，只做规则检测")

    sp_scan = sub.add_parser("scan", help="只检测，不调用模型")
    common(sp_scan)

    sp_audit = sub.add_parser("audit", help="检测 + 四段式可解释性分析")
    common(sp_audit)

    sp_fix = sub.add_parser("fix", help="检测 + 解释 + 生成补丁 + 机器验证")
    common(sp_fix)
    sp_fix.add_argument("--rounds", type=int, default=3, help="每个漏洞最多重试轮次")
    sp_fix.add_argument("--run-tests", action="store_true",
                        help="运行被审计仓库的测试做回归（默认关闭：等于执行该仓库的代码，仅对可信仓库开启）")
    sp_fix.add_argument("--no-tests", action="store_true",
                        help="强制不跑回归测试（默认即不跑；保留用于兼容旧用法）")
    sp_fix.add_argument("--apply", action="store_true", help="把已验证补丁写入原仓库（会先备份）")
    sp_fix.add_argument("--yes", action="store_true", help="跳过交互确认（--apply / --run-tests）")

    return p


def _collect_targets(target: Path, include: list[str] | None, exclude: list[str]) -> list[Path]:
    if target.is_file():
        return [target]
    return iter_source_files(target, include, exclude or None)


def _filter_findings(
    findings: list[Finding],
    include: list[str] | None,
    exclude: list[str],
    only_paths: set[str] | None = None,
) -> list[Finding]:
    """按 glob 与目标路径过滤 finding（semgrep 结果不走 scan_tree，需要后置过滤）。"""
    out: list[Finding] = []
    for f in findings:
        rel = f.path.replace("\\", "/")
        if only_paths is not None and rel not in only_paths:
            continue
        if include and not matches_globs(rel, include):
            continue
        if exclude and matches_globs(rel, exclude):
            continue
        out.append(f)
    return out


def _semgrep_scan(root: Path, config: str) -> tuple[list[Finding], str]:
    """调用 semgrep 后端，任何异常都降级为空结果。

    semgrep 是可选增强，不是安装门槛：镜像拉不下来、命令拼错、容器被杀，
    都只应该让这次扫描退回内置规则，而不是让整个 scan 崩掉。
    """
    from . import semgrep_backend

    try:
        return semgrep_backend.scan(root, config=config)
    except Exception as exc:  # noqa: BLE001 - 兜底就是为了不让可选项拖垮主流程
        return [], f"semgrep 后端异常，已忽略并退回内置规则：{type(exc).__name__}: {exc}"


def _detect_all(
    root: Path,
    rules: list,
    args: argparse.Namespace,
    *,
    only_paths: set[str] | None = None,
) -> tuple[list[Finding], list[str]]:
    """按选定的后端收集发现，返回 (findings, 说明)。

    include/exclude/单文件目标对所有后端生效：内置规则在遍历时剪枝，
    semgrep 结果在事后按同样语义过滤。
    """
    mode = getattr(args, "detector", "auto")
    config = getattr(args, "semgrep_config", "auto") or "auto"
    include = getattr(args, "include", None)
    exclude = getattr(args, "exclude", []) or []
    notes: list[str] = []

    if mode == "semgrep":
        found, note = _semgrep_scan(root, config)
        notes.append(note)
        found = _filter_findings(found, include, exclude, only_paths)
        if not found:
            from . import semgrep_backend

            notes.append(semgrep_backend.install_hint())
        return found, notes

    rule_findings = scan_tree(
        root, rules, include_globs=include, only_paths=list(only_paths or []),
        exclude_globs=exclude or None,
    )

    if mode == "rules":
        return rule_findings, ["内置规则引擎"]

    found, note = _semgrep_scan(root, config)
    notes.append(note)
    if not found:
        if mode == "both":
            notes.append("semgrep 未产出结果，本次仅使用内置规则")
        return rule_findings, notes

    found = _filter_findings(found, include, exclude, only_paths)
    notes.append(f"合并后共 {len(merge_findings(rule_findings, found))} 条（去重前 "
                 f"{len(rule_findings)} + {len(found)}）")
    return merge_findings(rule_findings, found), notes


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.exists():
        _progress(f"路径不存在: {target}")
        return 2

    rules = _select_rules(args.rule, args.rules_file)
    root = target if target.is_dir() else target.parent
    files = _collect_targets(target, args.include, args.exclude)
    only_paths = None if target.is_dir() else {target.name}

    findings, notes = _detect_all(root, rules, args, only_paths=only_paths)
    for note in notes:
        _progress(f"检测后端：{note}")

    findings = [
        f for f in findings
        if SEV_ORDER[f.severity] >= SEV_ORDER[Severity(args.min_severity.upper())]
    ]

    baseline_obj = None
    report_findings = findings
    known: list[Finding] = []
    if args.baseline:
        try:
            baseline_obj = baseline.load(args.baseline)
        except (OSError, ValueError) as exc:
            _progress(f"基线文件无法读取: {exc}")
            return 2
        report_findings, known = baseline.split(findings, baseline_obj)
        _progress(
            f"基线：{baseline.summary(baseline_obj)}；"
            f"本次已存在 {len(known)} 条，新增 {len(report_findings)} 条"
        )

    if args.limit:
        report_findings = report_findings[: args.limit]

    if args.json:
        print(json.dumps([_finding_dict(f) for f in report_findings], ensure_ascii=False, indent=2))
    else:
        if not report_findings:
            scope = f"（已过滤 {len(known)} 条基线内问题）" if baseline_obj else ""
            print(f"扫描 {len(files)} 个文件，无新增问题。{scope}")
        else:
            for f in report_findings:
                print(f"[{f.severity.value:7}] {f.location:40} {f.message}")
                print(f"          {f.rule_id}  {', '.join(f.cwe)}")
            print(f"\n扫描 {len(files)} 个文件，新增 {len(report_findings)} 条"
                  + (f"（另有 {len(known)} 条在基线内）" if baseline_obj else ""))

    if args.sarif:
        out = sarif.write(report_findings, args.sarif, tool_version=__version__)
        print(f"SARIF 已写入 {out}")

    if args.output:
        out = write_report(_scan_report(report_findings, target, len(files)), Path(args.output))
        print(f"报告已写入 {out}")

    if args.write_baseline:
        baseline.save(baseline.build(findings), args.write_baseline)
        print(f"基线已写入 {args.write_baseline}（{len(findings)} 条）")

    if args.fail_on_new and baseline_obj is not None and report_findings:
        _progress(f"存在 {len(report_findings)} 条基线之外的新问题，按 --fail-on-new 返回非零")
        return 1

    if args.fail_on_findings and report_findings:
        _progress(f"仍有 {len(report_findings)} 条发现，按 --fail-on-findings 返回非零")
        return 1

    return 0


def _scan_report(findings: list[Finding], target: Path, files: int) -> str:
    """scan 的 markdown 输出。audit/fix 走 render_report，这里只需要结果清单。"""
    lines = [
        "# 漏洞扫描报告",
        "",
        f"- 目标：`{getattr(target, 'name', target)}`",
        f"- 扫描文件：{files}",
        f"- 发现问题：{len(findings)}",
        "",
    ]
    if not findings:
        lines.append("无发现。")
        return "\n".join(lines)
    lines += ["| 级别 | 位置 | 规则 | 说明 |", "| --- | --- | --- | --- |"]
    for f in findings:
        code = (f.code_line or f.snippet or "").strip().replace("|", "\\|")[:80]
        lines.append(
            f"| {f.severity.value} | `{f.location}` | `{f.rule_id}` | {f.message}｜`{code}` |"
        )
    return "\n".join(lines)


def _make_results(
    args: argparse.Namespace,
    target: Path,
    do_fix: bool,
) -> tuple[list[RepairResult], int]:
    rules = _select_rules(args.rule, args.rules_file)
    root = target if target.is_dir() else target.parent

    files = _collect_targets(target, args.include, args.exclude)
    only_paths = None if target.is_dir() else {target.name}
    findings, notes = _detect_all(root, rules, args, only_paths=only_paths)
    for note in notes:
        _progress(f"检测后端：{note}")

    findings = [f for f in findings if SEV_ORDER[f.severity] >= SEV_ORDER[Severity(args.min_severity.upper())]]
    if args.limit:
        findings = findings[: args.limit]

    if not findings:
        return [], len(files)

    client = None
    if not args.no_llm:
        cfg = LLMConfig.from_env()
        if args.llm_base_url:
            cfg.base_url = args.llm_base_url.rstrip("/")
        if args.llm_key:
            cfg.api_key = args.llm_key
        if args.llm_model:
            cfg.model = args.llm_model
        client = LLMClient(cfg)
        if not cfg.usable:
            _progress("提示：未配置 API Key，解释会降级为规则先验，补丁不会生成。")
            _progress("      设置 BEE_LLM_API_KEY 后重跑可启用完整能力。")

    # 回归测试默认关闭：跑被审计仓库的测试等于执行它的代码，
    # 显式 --run-tests 才开，且要求确认知情。
    run_tests = bool(getattr(args, "run_tests", False)) and not getattr(args, "no_tests", False)
    if do_fix and run_tests and not getattr(args, "yes", False) and sys.stdin.isatty():
        _progress("注意：--run-tests 会执行被审计仓库的测试代码（即该仓库可以执行任意 Python/JS）。")
        answer = input("确认运行？[y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            run_tests = False
            _progress("已按用户选择跳过回归测试。")
    if do_fix and not run_tests:
        _progress("回归测试默认关闭（--run-tests 开启）。验证到「重扫 + 语法」层。")

    from .context import build_context

    # 同一文件多处漏洞要累积修复，否则后一条补丁的上下文会被前一条改掉
    session = PatchSession(root)

    results: list[RepairResult] = []
    total = len(findings)
    for i, f in enumerate(findings, 1):
        _progress(f"[{i}/{total}] {f.location}  {f.message}")
        ctx = build_context(f, root)
        expl = explain(f, ctx, client, root)
        result = RepairResult(finding=f, explanation=expl)

        if do_fix and client is not None and client.config.usable:
            if expl.degraded:
                # 证据校验不合格的解释不能当「已确认根因」喂给补丁——
                # 编造的根因会把补丁直接带偏。宁可标成仅解释。
                _progress(f"       ⚠️ 解释未通过证据校验（{expl.degrade_reason[:80]}），跳过补丁生成")
                results.append(result)
                continue

            # 先看当前累积状态下这个漏洞是否还在——可能已被前一条补丁顺带修掉
            base = session.base_text(f.path)
            if base is not None and not finding_still_present(f, base, root, rules):
                result.covered_elsewhere = True
                _progress("       ⊘ 已被前述补丁覆盖，跳过")
                results.append(result)
                continue

            attempts = repair_finding(
                f, expl, ctx, client, root,
                max_rounds=getattr(args, "rounds", 3),
                run_tests=run_tests,
                session=session,
                rules=rules,
            )
            result.attempts = attempts
            result.accepted = next((a for a in attempts if a.succeeded), None)
            if result.accepted:
                _progress("       ✅ 补丁通过验证")
            elif attempts:
                _progress(f"       ⚠️ {attempts[-1].failure_reason()}")
        results.append(result)

    setattr(args, "_session", session)
    return results, len(files)


def _emit(args: argparse.Namespace, results: list[RepairResult], target: Path, files: int) -> int:
    if args.json:
        payload = []
        for r in results:
            payload.append({
                "finding": {
                    "rule_id": r.finding.rule_id,
                    "severity": r.finding.severity.value,
                    "path": r.finding.path,
                    "line": r.finding.start_line,
                    "cwe": r.finding.cwe,
                    "message": r.finding.message,
                },
                "explanation": r.explanation.__dict__ if r.explanation else None,
                "status": r.status,
                "attempts": [a.__dict__ for a in r.attempts],
            })
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        print(render_console(results))

    if args.output:
        content = render_report(
            results, target, files, display_path=getattr(args, "target", None)
        )
        out = write_report(content, Path(args.output))
        print(f"\n报告已写入 {out}")

    if getattr(args, "sarif", None):
        out = sarif.write([r.finding for r in results], args.sarif, tool_version=__version__)
        print(f"SARIF 已写入 {out}")

    if getattr(args, "write_baseline", None):
        baseline.save(baseline.build([r.finding for r in results]), args.write_baseline)
        print(f"基线已写入 {args.write_baseline}")

    if getattr(args, "fail_on_findings", False) and any(
        not r.covered_elsewhere for r in results
    ):
        _progress(f"仍有 {sum(1 for r in results if not r.covered_elsewhere)} 条未消除的发现，"
                  f"按 --fail-on-findings 返回非零")
        return 1

    return 0


def cmd_audit_or_fix(args: argparse.Namespace, do_fix: bool) -> int:
    target = Path(args.target).resolve()
    if not target.exists():
        _progress(f"路径不存在: {target}")
        return 2

    results, files = _make_results(args, target, do_fix)
    if not results:
        print(f"扫描 {files} 个文件，未发现问题。")
        return 0

    session: PatchSession | None = getattr(args, "_session", None)
    root = target if target.is_dir() else target.parent

    if do_fix and getattr(args, "apply", False) and session is not None:
        if session.count() == 0:
            print("没有通过验证的补丁，无需落盘。")
        else:
            touched = session.files_touched()
            print(f"\n即将把 {session.count()} 处修改写入 {len(touched)} 个文件：")
            for rel in touched:
                print(f"  - {rel}（{session.count_for(rel)} 处）")
            print("  每个文件会先生成 .bee.bak 备份，同一文件的修改按验证顺序应用")

            proceed = True
            if not getattr(args, "yes", False):
                answer = input("\n确认写入？[y/N] ").strip().lower()
                proceed = answer in {"y", "yes"}
            if not proceed:
                print("已取消落盘。报告中的 diff 仍可手工应用。")
            else:
                written, errors = apply_session(root, session)
                print(f"已写入 {written} 个文件。")
                for err in errors:
                    print(f"  ✗ {err}")

    return _emit(args, results, target, files)


def _force_utf8_output() -> None:
    """把 stdout/stderr 切到 UTF-8。

    报告和进度提示都是中文。CI 里如果 locale 是 C/POSIX，Python 3.12 的
    stdout 编码会是 ascii，第一次 print 中文就抛 UnicodeEncodeError——
    工具本身没问题，却在最不该挂的地方挂掉。这里统一兜住。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            continue


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    # 启动时清理异常退出遗留的临时副本（里面可能含密钥文件，不能长期留在 temp）
    try:
        cleanup_stale_temp()
    except Exception:
        pass

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "audit":
        return cmd_audit_or_fix(args, do_fix=False)
    if args.command == "fix":
        return cmd_audit_or_fix(args, do_fix=True)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""可选的 semgrep 后端。

为什么内置规则之外还要接 semgrep：自建 30 条规则的覆盖面，和 semgrep
社区几千条规则不在一个量级。真实项目里覆盖率决定它有没有用。

但 semgrep 在 Windows 上依赖 WSL 或 Docker，不是所有环境都有。
所以这里的定位是**可选增强**：探测得到就用，探测不到就静默回退，
绝不让它成为安装门槛。

调用方式按优先级：本地 semgrep 命令 → docker 镜像 → 不可用。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .models import Finding, Severity, TraceStep

_SEMGREP_TIMEOUT = 900


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 127, str(exc)


def probe() -> tuple[str, list[str]]:
    """返回 (模式, 命令前缀)。

    模式取值：local / docker / none
    """
    if shutil.which("semgrep"):
        code, _ = _run(["semgrep", "--version"], timeout=30)
        if code == 0:
            return "local", ["semgrep"]

    if shutil.which("docker"):
        code, out = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
        if code == 0 and out.strip():
            return "docker", ["docker"]

    return "none", []


def _build_command(
    mode: str, prefix: list[str], root: Path, config: str, target_rel: str
) -> list[str]:
    if mode == "local":
        return prefix + ["--json", "--quiet", "--config", config, target_rel]

    # docker：把项目目录挂进 /src，semgrep 在容器内的路径都是 /src 下
    mount = f"{root.resolve()}:/src"
    return prefix + [
        "run", "--rm",
        "-v", mount,
        "-w", "/src",
        "returntocorp/semgrep:latest",
        "semgrep", "--json", "--quiet", "--config", config, target_rel,
    ]


def _severity(raw: str) -> Severity:
    return {
        "ERROR": Severity.ERROR,
        "WARNING": Severity.WARNING,
        "INFO": Severity.INFO,
    }.get(str(raw).upper(), Severity.WARNING)


def _cwe_list(meta: dict) -> list[str]:
    out: list[str] = []
    raw = meta.get("cwe")
    items = raw if isinstance(raw, list) else [raw] if raw else []
    for item in items:
        text = str(item)
        # semgrep 写成 "CWE-89: Improper Neutralization..."，只取编号
        head = text.split(":", 1)[0].strip()
        if head.upper().startswith("CWE-"):
            out.append(head.upper())
    # 同一编号在 metadata 里常以不同描述出现多次；不去重会让 SARIF tags 违反
    # uniqueItems，GitHub Code Scanning 会直接拒收整份文件。
    return list(dict.fromkeys(out))


def _owasp_list(meta: dict) -> list[str]:
    raw = meta.get("owasp")
    items = raw if isinstance(raw, list) else [raw] if raw else []
    out = []
    for item in items:
        # semgrep 写成 "A03:2021 - Injection"；要保留 "A03:2021" 整段，
        # 按 ":" 切会把年份切掉，只剩 "A03"，跟内置规则的 "A03:2021" 对不上。
        m = re.match(r"\s*(A\d{2}(?::\d{4})?)", str(item))
        if m:
            out.append(m.group(1))
    return list(dict.fromkeys(out))


def _parse_trace(item: dict, root: Path) -> list[TraceStep]:
    """把 semgrep 的污点路径转成统一的 TraceStep 列表。

    这条信息是可解释性的核心原料：有了 source→sink 的具体位置，
    模型才能说清数据是怎么流进来的，而不是复述 CWE 定义。
    """
    trace = (item.get("extra") or {}).get("dataflow_trace")
    if not isinstance(trace, dict):
        return []

    steps: list[TraceStep] = []

    def _loc(payload: object, label: str) -> None:
        # 形如 ["CliLoc", [{path, start:{line}, end:{line}, content}]]
        if not isinstance(payload, list) or len(payload) < 2:
            return
        entries = payload[1]
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            path = str(entry.get("path") or "")
            line = int((entry.get("start") or {}).get("line") or 0)
            content = str(entry.get("content") or "")
            if path:
                try:
                    path = str(Path(path).resolve().relative_to(root.resolve())).replace("\\", "/")
                except (ValueError, OSError):
                    path = path.replace("\\", "/")
            steps.append(TraceStep(label=label, path=path, line=line, content=content[:300]))

    _loc(trace.get("taint_source"), "source")
    for mid in trace.get("intermediate_vars") or []:
        if not isinstance(mid, dict):
            continue
        loc = mid.get("location") or {}
        path = str(loc.get("path") or "")
        line = int((loc.get("start") or {}).get("line") or 0)
        if path:
            steps.append(
                TraceStep(
                    label="intermediate", path=path.replace("\\", "/"), line=line,
                    content=str(mid.get("content") or "")[:300],
                )
            )
    _loc(trace.get("taint_sink"), "sink")
    return steps


def _to_finding(item: dict, root: Path) -> Finding | None:
    path = str(item.get("path") or "").replace("\\", "/")
    if not path:
        return None
    try:
        rel = str(Path(path).resolve().relative_to(root.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        rel = path

    extra = item.get("extra") or {}
    meta = extra.get("metadata") or {}
    start = int((item.get("start") or {}).get("line") or 1)
    end = int((item.get("end") or {}).get("line") or start)
    snippet = str(extra.get("lines") or "").strip()

    return Finding(
        rule_id=str(item.get("check_id") or "semgrep.unknown"),
        severity=_severity(extra.get("severity", "WARNING")),
        message=str(extra.get("message") or item.get("check_id") or "semgrep finding").strip(),
        path=rel,
        start_line=start,
        end_line=max(end, start),
        cwe=_cwe_list(meta),
        owasp=_owasp_list(meta),
        references=[str(x) for x in (meta.get("references") or [])][:5]
        if isinstance(meta.get("references"), list) else [],
        trace=_parse_trace(item, root),
        snippet=snippet,
        code_line=snippet.splitlines()[0].strip() if snippet else "",
        detector="semgrep",
        raw={
            "title": str(meta.get("shortDescription") or item.get("check_id") or ""),
            "root_cause_hint": str(extra.get("message") or ""),
            "fix_hint": str(meta.get("fix") or ""),
            "matched": snippet[:400],
            "confidence": str(meta.get("confidence") or ""),
            "impact": str(meta.get("impact") or ""),
        },
    )


def scan(
    root: Path,
    *,
    config: str = "auto",
    target_rel: str = ".",
    mode: str | None = None,
    extra_args: list[str] | None = None,
) -> tuple[list[Finding], str]:
    """跑一次 semgrep。返回 (findings, 说明信息)。

    说明信息用于在报告里交代「用了哪个后端、什么规则集」，
    这样别人看到结果时知道覆盖面边界在哪。
    """
    detected_mode, prefix = probe() if mode in (None, "auto") else (mode, _prefix_for(mode))
    if detected_mode == "none" or not prefix:
        return [], "semgrep 不可用（未找到 semgrep 命令，也未找到可运行的 docker）"

    cmd = _build_command(detected_mode, prefix, root, config, target_rel)
    if extra_args:
        cmd.extend(extra_args)

    code, out = _run(cmd, cwd=root, timeout=_SEMGREP_TIMEOUT)
    payload = _extract_json(out)
    if payload is None:
        reason = out.strip().splitlines()[-1][:300] if out.strip() else f"退出码 {code}"
        return [], f"semgrep 执行失败：{reason}"

    findings: list[Finding] = []
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        converted = _to_finding(item, root)
        if converted is not None:
            findings.append(converted)

    where = "本地 semgrep" if detected_mode == "local" else "docker 镜像 semgrep"
    return findings, f"semgrep 后端已启用（{where}，规则集 {config}）"


def _prefix_for(mode: str) -> list[str]:
    if mode == "local":
        return ["semgrep"]
    if mode == "docker":
        return ["docker"]
    return []


def _extract_json(output: str) -> dict | None:
    """semgrep 的 stdout 是纯 JSON，但 stderr 可能被合并进来，所以做一次截取。"""
    text = output.strip()
    if not text:
        return None
    start = text.find("{")
    if start < 0:
        return None
    # 从最后一个 } 往前找，避免日志尾部干扰
    end = text.rfind("}")
    if end <= start:
        return None
    try:
        return json.loads(text[start: end + 1])
    except json.JSONDecodeError:
        return None


def install_hint() -> str:
    if sys.platform == "win32":
        return (
            "Windows 上 semgrep 需要 WSL 或 Docker。安装方式：\n"
            "  - 启动 Docker Desktop 后重跑（会自动使用 returntocorp/semgrep 镜像）\n"
            "  - 或在 WSL 里 pip install semgrep\n"
            "不装也能用：内置 30 条规则不需要任何外部依赖。"
        )
    return "pip install semgrep 或使用 docker 镜像 returntocorp/semgrep"

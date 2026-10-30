"""外部规则 → 内置规则映射。

用途只有一个：`bee audit --input semgrep.sarif` 时，外部 finding 原本的 rule_id
（如 `python.lang.security.audit.formatted-sql-query`）在本地没有同名规则，
重扫必然扫不到，于是 `finding_gone` 只能记 `None`，整条「修复 → 验证」闭环断掉。

映射表让一部分外部 finding 能借用等价的内置规则重扫，从而拿到真正的
`finding_gone: True/False`。

分两层，可信度不同：

1. `EXPLICIT` —— 人工确认过的精确映射。命中即视为可信，不提示。
2. `heuristic()` —— 按规则名后缀猜。只在用户显式给了 `--rescan-rules`
   时启用，且报告里会标注「映射是推测的」。

为什么不干脆全自动猜：猜错的方向是「用 bee.sql-injection 判定一个 XSS finding
是否消失」，结论会反着来。宁可少验证，不能假验证。
"""

from __future__ import annotations

from .models import Finding

# 人工确认：Semgrep 与 CodeQL 的高频规则 → bee 内置规则。
# 只收「语义确实等价」的；那些只是相关但不重叠的（如 semgrep 的
# `audit.request-data-write`）一律不放，留着走「未验证」。
EXPLICIT: dict[str, str] = {
    # ---- Semgrep
    "python.lang.security.audit.formatted-sql-query": "bee.sql-injection",
    "python.lang.security.audit.python-sql-injection": "bee.sql-injection",
    "python.lang.security.audit.dangerous-subprocess-use": "bee.command-injection",
    "python.lang.security.audit.subprocess-shell-true": "bee.command-injection",
    "python.lang.security.audit.eval-detected": "bee.code-injection",
    "python.lang.security.audit.exec-detected": "bee.code-injection",
    "python.lang.security.deserialization.unsafe-deserialization": "bee.unsafe-deserialization",
    "python.lang.security.audit.unsafe-deserialization": "bee.unsafe-deserialization",
    "python.lang.security.audit.path-traversal": "bee.path-traversal",
    "python.lang.security.audit.hardcoded-password": "bee.hardcoded-credential",
    "python.lang.security.audit.hardcoded-token": "bee.hardcoded-credential",
    "python.lang.security.audit.insecure-hash-algorithm-md5": "bee.weak-crypto",
    "python.lang.security.audit.insecure-hash-algorithm-sha1": "bee.weak-crypto",
    "python.lang.security.audit.weak-ssl-version": "bee.tls-verify-disabled",
    "python.lang.security.audit.requests-verify-false": "bee.tls-verify-disabled",
    "python.lang.security.audit.insecure-transport": "bee.tls-verify-disabled",
    "javascript.lang.security.audit.innerhtml": "bee.xss",
    "javascript.express.security.audit.express-res-sendfile": "bee.path-traversal",
    "javascript.lang.security.audit.prototype-pollution": "bee.prototype-pollution",
    # ---- CodeQL
    "py/sql-injection": "bee.sql-injection",
    "py/command-line-injection": "bee.command-injection",
    "py/code-injection": "bee.code-injection",
    "py/path-injection": "bee.path-traversal",
    "py/unsafe-deserialization": "bee.unsafe-deserialization",
    "py/weak-sensitive-data-hashing": "bee.weak-crypto",
    "py/weak-cryptographic-algorithm": "bee.weak-crypto",
    "py/hardcoded-credentials": "bee.hardcoded-credential",
    "py/clear-text-logging-sensitive-data": "bee.sensitive-data-logging",
    "py/xml-bomb": "bee.xxe",
    "py/xxe": "bee.xxe",
    "py/url-redirection": "bee.open-redirect",
    "py/request-without-cert-validation": "bee.tls-verify-disabled",
    "py/stack-trace-exposure": "bee.debug-enabled",
    "js/sql-injection": "bee.sql-injection",
    "js/code-injection": "bee.code-injection",
    "js/command-line-injection": "bee.command-injection",
    "js/path-injection": "bee.path-traversal",
    "js/xss": "bee.xss",
    "js/prototype-pollution-utility": "bee.prototype-pollution",
    "js/insecure-randomness": "bee.insecure-random",
}

# 猜测用：规则名里出现这些词就认为语义相近。顺序有意义——
# 先匹配到的先用（`sql` 比 `injection` 具体）。
_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("sql",), "bee.sql-injection"),
    (("nosql", "mongo"), "bee.nosql-injection"),
    (("ldap",), "bee.ldap-injection"),
    (("deserial", "pickle", "yaml-load"), "bee.unsafe-deserialization"),
    (("xxe", "xml-external", "xml-bomb"), "bee.xxe"),
    (("ssti", "template-injection"), "bee.ssti"),
    (("ssrf",), "bee.ssrf"),
    (("redirect",), "bee.open-redirect"),
    (("xss", "innerhtml", "html-injection"), "bee.xss"),
    (("prototype-pollution",), "bee.prototype-pollution"),
    (("zip-slip", "tar-slip", "archive-extract"), "bee.zip-slip"),
    (("path-traversal", "path-injection", "directory-traversal"), "bee.path-traversal"),
    (("command-injection", "command-line-injection", "subprocess"), "bee.command-injection"),
    (("eval", "exec", "code-injection"), "bee.code-injection"),
    (("weak-crypto", "insecure-hash", "md5", "sha1"), "bee.weak-crypto"),
    (("tls", "ssl", "cert", "verify-false"), "bee.tls-verify-disabled"),
    (("hardcoded", "credential", "password", "secret", "apikey"), "bee.hardcoded-credential"),
    (("insecure-random", "weak-random", "randomness"), "bee.insecure-random"),
    (("jwt",), "bee.jwt-verify-disabled"),
    (("cors",), "bee.cors-wildcard"),
    (("csrf",), "bee.csrf-disabled"),
    (("redos", "catastrophic"), "bee.redos"),
    (("log-injection", "logging-sensitive"), "bee.sensitive-data-logging"),
    (("upload",), "bee.unrestricted-upload"),
    (("cookie",), "bee.insecure-cookie"),
]


def _candidates(rule_id: str) -> list[str]:
    """把外部 rule_id 拆成可匹配的片段，从最具体到最泛。"""
    low = rule_id.lower().replace("_", "-")
    parts = [p for p in low.replace("/", ".").split(".") if p]
    out = [low]
    # 从右往左逐段拼：`python.lang.security.audit.formatted-sql-query`
    # 也会产出 `audit.formatted-sql-query`、`formatted-sql-query`
    for i in range(len(parts) - 1, 0, -1):
        out.append("-".join(parts[i:]))
    return out


def heuristic(rule_id: str, known: set[str]) -> str:
    """按名字猜一个等价的内置规则；猜不到返回空串。"""
    for cand in _candidates(rule_id):
        for words, target in _HINTS:
            if target not in known:
                continue
            if any(w in cand for w in words):
                return target
    return ""


def resolve(rule_id: str, known: set[str], *, allow_guess: bool = False) -> tuple[str, bool]:
    """返回 (本地规则 id, 是否属于猜测)。解析不到时返回 ("", False)。

    known 是当前可用的规则 id 集合——映射到一条没被加载的规则没有意义。
    """
    if rule_id in known:
        return rule_id, False
    hit = EXPLICIT.get(rule_id)
    if hit and hit in known:
        return hit, False
    if allow_guess:
        guess = heuristic(rule_id, known)
        if guess:
            return guess, True
    return "", False


def annotate(
    findings: list[Finding], known: set[str], *, allow_guess: bool = False
) -> tuple[int, int, list[str]]:
    """给外部 finding 补上 rescan_rule_id。

    返回 (已映射条数, 其中靠猜的条数, 未能映射的 rule_id 列表)。
    """
    mapped = guessed = 0
    unmapped: list[str] = []
    seen_unmapped: set[str] = set()
    for f in findings:
        target, is_guess = resolve(f.rule_id, known, allow_guess=allow_guess)
        if not target:
            if f.rule_id not in seen_unmapped:
                seen_unmapped.add(f.rule_id)
                unmapped.append(f.rule_id)
            continue
        if target != f.rule_id:
            f.rescan_rule_id = target
        # 有等价规则了，重扫才允许——否则「扫不到」会被当成「修好了」
        f.rescan_ok = True
        mapped += 1
        if is_guess:
            guessed += 1
    return mapped, guessed, unmapped

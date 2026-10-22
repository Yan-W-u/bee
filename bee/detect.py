"""检测层：规则引擎 + LLM 语义审计双通道。

为什么不用 semgrep：Windows 环境下 semgrep 依赖 WSL 或 Docker，两者都不可靠。
自建规则引擎有额外好处 —— 每条规则自带 root_cause_hint / fix_hint，
这是可解释性分析的先验知识，比纯正则信号强得多。

设计取舍：宁可少而准。误报会摧毁可解释性修复的可信度，
因为你会花半页篇幅解释一个根本不存在的漏洞。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .io_utils import read_source
from .models import Finding, Severity

# ---------------------------------------------------------------- 规则定义


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    cwe: list[str]
    owasp: list[str]
    languages: list[str]
    pattern: str
    # 命中这些正则说明代码已经是安全的，用于压制误报
    safe_when: list[str] = field(default_factory=list)
    # 必须同时命中才成立（用于要求"这个变量确实来自外部输入"这类条件）
    require: list[str] = field(default_factory=list)
    root_cause_hint: str = ""
    fix_hint: str = ""
    references: list[str] = field(default_factory=list)


def _r(*rules: Rule) -> list[Rule]:
    return list(rules)


# 语言通用性说明：pattern 用宽松的正则写法，由 languages 决定是否套用
BUILTIN_RULES: list[Rule] = _r(
    Rule(
        id="bee.sql-injection",
        title="SQL 注入（字符串拼接构造查询）",
        severity=Severity.ERROR,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:execute|executemany|query|raw|exec)\s*\(\s*(?:f?["']|`)[^;]{0,400}?(?:select|insert|update|delete|replace)\b[^;]{0,400}?(?:\+\s*\w|%\s*\(|%\s*\w|\$\{|["']\s*\+|\.\s*format\s*\(|\{)""",
        safe_when=[
            r"(?i)\)\s*,\s*[\(\[\{]",  # 参数化查询 (sql, params)
            r"(?i)\bbindParam|\bplaceholder|=\s*\?\s*\)",
        ],
        root_cause_hint="用户可控数据被直接拼进 SQL 文本，数据库无法区分代码与数据边界。",
        fix_hint="改为参数化查询（占位符 + 参数绑定），让驱动负责转义；不要用任何字符串拼接或 f-string/format。",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    ),
    Rule(
        id="bee.command-injection",
        title="OS 命令注入",
        severity=Severity.ERROR,
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call)|child_process\.exec(?:Sync)?|Runtime\.getRuntime\(\)\.exec|exec\.Command)\s*\(\s*(?:f["']|["'`])[^)]{0,300}?(?:\+\s*\w|\$\{|\{\w*\}|\.format\s*\()|shell\s*=\s*True)""",
        safe_when=[
            r"(?i)shell\s*=\s*False",
            r"(?i)\bshlex\.quote\b|\bshlex\.join\b",
        ],
        root_cause_hint="外部输入被交给 shell 解释执行，shell 会把它当作命令语法而不是普通文本。",
        fix_hint="改用参数列表形式（shell=False）调用，或用 shlex.quote / 白名单校验；优先避免调用 shell。",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    Rule(
        id="bee.path-traversal",
        title="路径穿越（未校验的文件路径拼接）",
        severity=Severity.ERROR,
        cwe=["CWE-22"],
        owasp=["A01:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:open|readFile|readFileSync|createReadStream|send_file|sendFile|ioutil\.ReadFile|os\.ReadFile|FileInputStream)\s*\(\s*(?:os\.path\.join\s*\([^)]{0,200}\w|path\.join\s*\([^)]{0,200}\w|filepath\.Join\s*\([^)]{0,200}\w)[^)]{0,200}\)?""",
        safe_when=[
            r"(?i)secure_filename|\bbasename\b|\brealpath\b|\bResolve\b.*\bHasPrefix\b|\bcommonpath\b|\bfromfilepath\b",
        ],
        require=[],
        root_cause_hint="用户可控的文件名进入路径拼接，`../` 可以跳出预期目录，读写任意文件。",
        fix_hint="先规范化路径（realpath/clean），再校验结果仍在允许的根目录内；或只接受 basename 并用白名单限制扩展名。",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
    ),
    Rule(
        id="bee.hardcoded-credential",
        title="硬编码凭据",
        severity=Severity.WARNING,
        cwe=["CWE-798"],
        owasp=["A07:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php", "yaml", "json", "env"],
        # 用零宽后视而不是 [^A-Za-z0-9]：后者会吞掉换行符，导致行号整体偏移 1。
        pattern=r"""(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9_.]*)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|credential)[A-Za-z0-9_]*\s*(?<![=!<>])=(?!=)\s*["'][^"'\s]{6,}["']""",
        safe_when=[
            r"(?i)(?:os\.getenv|os\.environ|process\.env|getenv\(|env::var|\$\{|<[a-z_-]+>|xxx+|YOUR_|PLACEHOLDER|CHANGE_?ME|example|dummy|test|sample|your-|\*\*\*)",
        ],
        root_cause_hint="凭据以明文写死在源码中，会随仓库、镜像、日志一起扩散，且无法按环境轮换。",
        fix_hint="改为从环境变量或密钥管理服务读取，并在启动时做缺失校验；同时轮换已泄露的凭据。",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    Rule(
        id="bee.unsafe-deserialization",
        title="不安全反序列化",
        severity=Severity.ERROR,
        cwe=["CWE-502"],
        owasp=["A08:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)\b(?:pickle\.loads?|cPickle\.loads?|yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)|marshal\.loads|shelve\.open|ObjectInputStream|readObject\s*\(|unserialize\s*\()""",
        safe_when=[r"(?i)SafeLoader|safe_load|json\.loads?|literal_eval"],
        root_cause_hint="反序列化格式允许携带可执行对象引用，加载过程本身就会调用构造逻辑，等价于执行任意代码。",
        fix_hint="换成纯数据格式（JSON）或使用 SafeLoader / 白名单类加载；不要反序列化不可信来源的数据。",
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    Rule(
        id="bee.code-injection",
        title="动态代码执行（eval/exec 类）",
        severity=Severity.ERROR,
        cwe=["CWE-94", "CWE-95"],
        owasp=["A03:2021"],
        languages=["python", "javascript", "typescript", "php"],
        pattern=r"""(?is)\b(?:eval|exec|execfile|compile|new\s+Function|Function\s*\(|setTimeout\s*\(\s*["'`]|assert\s*\()\s*\(\s*(?:f["']|[^)]{0,120}(?:\+|request\.|input\(|\$\{))""",
        safe_when=[r"(?i)ast\.literal_eval|json\.parse"],
        root_cause_hint="字符串被当作代码解析执行，一旦内容可被外部影响，就等于把解释器交给了攻击者。",
        fix_hint="用显式映射表或 AST 白名单替代动态求值；确实需要表达式时用 literal_eval / 受限解析器。",
        references=["https://cwe.mitre.org/data/definitions/94.html"],
    ),
    Rule(
        id="bee.ssrf",
        title="SSRF（外部可控的请求目标）",
        severity=Severity.WARNING,
        cwe=["CWE-918"],
        owasp=["A10:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)\b(?:requests\.(?:get|post|put|delete|head|request)|httpx\.(?:get|post|request)|axios(?:\.(?:get|post|request))?|fetch|http\.Get|http\.Post|HttpClient|curl_exec|urllib\.request\.urlopen|urlopen|urlretrieve)\s*\(\s*(?:f["']|[^)\n]{0,120}(?:request\.(?:args|form|json|GET|POST|params)|params\[|body\[|\$\{))""",
        safe_when=[r"(?i)allowlist|whitelist|ALLOWED_HOSTS|urlparse\(.*\)\.netloc\s+in"],
        root_cause_hint="请求目标由外部输入决定，攻击者可让服务器去访问内网地址或云元数据端点。",
        fix_hint="对目标做协议+主机白名单校验，禁止内网/回环/链路本地地址；重定向后需重新校验。",
        references=["https://cwe.mitre.org/data/definitions/918.html"],
    ),
    Rule(
        id="bee.weak-crypto",
        title="弱加密算法",
        severity=Severity.WARNING,
        cwe=["CWE-327", "CWE-328"],
        owasp=["A02:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)\b(?:hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)|createHash\s*\(\s*["'](?:md5|sha1)|crypto\.(?:MD5|SHA1)|md5\.New|crypto\.createHash\s*\(\s*["']md5)""",
        safe_when=[],
        root_cause_hint="MD5/SHA-1 已被证明存在实用碰撞攻击，不能用于完整性校验或凭据存储。",
        fix_hint="换 SHA-256 及以上；口令存储用 bcrypt/scrypt/argon2 而非任何裸哈希。",
        references=["https://cwe.mitre.org/data/definitions/327.html"],
    ),
    Rule(
        id="bee.insecure-random",
        title="不安全随机数用于安全场景",
        severity=Severity.WARNING,
        cwe=["CWE-330", "CWE-338"],
        owasp=["A02:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)\b(?:random\.(?:random|randint|choice|randrange|sample)|Math\.random|mt_rand)\s*\([^)]*\)""",
        require=[r"(?i)\b(?:token|secret|password|salt|nonce|session|otp|reset|csrf|verif|key)\w*\b"],
        root_cause_hint="伪随机数生成器可预测，知道种子或观察到输出序列即可推算后续值。",
        fix_hint="安全场景改用 secrets / crypto.randomBytes / crypto/rand 等密码学安全随机源。",
        references=["https://cwe.mitre.org/data/definitions/330.html"],
    ),
    Rule(
        id="bee.xss",
        title="XSS（未转义的输出）",
        severity=Severity.WARNING,
        cwe=["CWE-79"],
        owasp=["A03:2021"],
        languages=["javascript", "typescript", "python", "php", "java"],
        pattern=r"""(?is)(?:innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|\.html\s*\(\s*[^)\s]*(?:\+|\$\{)|render_template_string\s*\(|Markup\s*\()""",
        safe_when=[r"(?i)DOMPurify|sanitize|escape\(|escapeHtml|textContent\s*="],
        root_cause_hint="未经转义的数据被当作 HTML 解释，浏览器无法区分内容与标记。",
        fix_hint="改用 textContent / 模板自动转义；必须渲染富文本时用 DOMPurify 等白名单净化。",
        references=["https://cwe.mitre.org/data/definitions/79.html"],
    ),
    Rule(
        id="bee.tls-verify-disabled",
        title="禁用 TLS 证书校验",
        severity=Severity.WARNING,
        cwe=["CWE-295"],
        owasp=["A07:2021"],
        languages=["python", "javascript", "typescript", "go", "java"],
        pattern=r"""(?is)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|TrustAllCerts|checkServerIdentity\s*:\s*\(\s*\)\s*=>|_create_unverified_context|CERT_NONE|check_hostname\s*=\s*False)""",
        safe_when=[],
        root_cause_hint="关闭证书校验后，中间人可以用任意证书冒充服务端，加密通道形同虚设。",
        fix_hint="恢复校验证书链与主机名；自签场景改为显式信任指定 CA，而不是全局关闭。",
        references=["https://cwe.mitre.org/data/definitions/295.html"],
    ),
    Rule(
        id="bee.debug-enabled",
        title="生产环境开启调试模式",
        severity=Severity.INFO,
        cwe=["CWE-489"],
        owasp=["A05:2021"],
        languages=["python", "javascript", "typescript", "go", "php"],
        pattern=r"""(?is)(?:\bapp\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True|debug\s*:\s*true\s*,|\bapp\.debug\s*=\s*True)""",
        safe_when=[r"(?i)os\.getenv|os\.environ|process\.env|is_dev|development"],
        root_cause_hint="调试模式会暴露堆栈、配置与交互式调试器，等于给攻击者一个内置的后门入口。",
        fix_hint="从环境变量读取 debug 开关，默认 False；生产部署显式关闭。",
        references=["https://cwe.mitre.org/data/definitions/489.html"],
    ),
)


# ---------------------------------------------------------------- 引擎

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".go": "go", ".java": "java", ".php": "php",
    ".rb": "ruby", ".rs": "rust", ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".h": "c",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".env": "env",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".next", "target", "vendor", ".idea", ".vscode", ".pytest_cache", ".mypy_cache",
    "site-packages", ".tox", "coverage", "htmlcov",
}

MAX_FILE_BYTES = 800_000


def detect_language(path: Path) -> str:
    if path.name == ".env" or path.suffix == ".env":
        return "env"
    return EXT_LANG.get(path.suffix.lower(), "")


def iter_source_files(root: Path, include_globs: list[str] | None = None) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            continue
        if not detect_language(p):
            continue
        if include_globs and not any(p.match(g) for g in include_globs):
            continue
        files.append(p)
    return sorted(files)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """把跨行续写的语句合并成一条逻辑行，返回 [(起始行号, 内容)]。

    没有这一步，`sql = (\n "SELECT..." + kw\n)` 这种写法会被漏掉。
    """
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    depth = 0
    start = 0

    for i, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        buf.append(line)
        stripped = line.rstrip()
        continued = stripped.endswith("\\")
        depth += (
            line.count("(") + line.count("[") + line.count("{")
            - line.count(")") - line.count("]") - line.count("}")
        )
        if depth <= 0 and not continued:
            out.append((start, "\n".join(buf)))
            buf = []
            depth = 0
    if buf:
        out.append((start, "\n".join(buf)))
    return out


SQL_KEYWORD_RE = re.compile(
    r"(?is)\b(?:select\b.{0,300}?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|"
    r"delete\s+from\b|drop\s+table\b|truncate\s+table\b)"
)
# 字符串被外部数据拼接/插值的信号
CONCAT_SIGNAL_RE = re.compile(
    r"""(?:["'`]\s*\+\s*\w)|(?:\w\s*\+\s*["'`])|(?:%\s*[\(\w])|(?:\.format\s*\()|(?:\bf["'])|(?:\$\{)"""
)
ASSIGN_RE = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*=\s*(.+)$", re.S)


def _split_call_args(text: str, open_idx: int) -> list[str]:
    """从 '(' 的位置开始做括号配对，按顶层逗号切分参数。

    必须真解析而不是靠正则，原因很实际：参数化查询里
    execute("... LIKE ?", ("%" + kw + "%",))
    第二个参数本身就有字符串拼接，用正则看会误判成 SQL 拼接注入。
    """
    if open_idx < 0 or open_idx >= len(text) or text[open_idx] != "(":
        return []
    args: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = ""
    i = open_idx

    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote and text[i - 1] != "\\":
                quote = ""
        elif ch in "\"'`":
            quote = ch
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            if depth > 1:
                buf.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(buf))
                return args
            buf.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(buf))
            buf = []
        else:
            if depth >= 1:
                buf.append(ch)
        i += 1
    return args


def _is_parameterized_sql_call(text: str, from_pos: int) -> bool:
    """判断 from_pos 附近的那次 execute 调用是否用了参数绑定。

    条件：至少两个参数，且第一个参数（SQL 文本）不含任何拼接/插值信号。
    """
    m = re.compile(r"\b(?:execute|executemany|executescript|query|raw)\s*\(", re.I).search(text, from_pos)
    if not m:
        return False
    open_idx = text.find("(", m.start())
    args = _split_call_args(text, open_idx)
    if len(args) < 2:
        return False
    first = args[0].strip()
    return not CONCAT_SIGNAL_RE.search(first)


def _detect_sql_flow(text: str, rel: str) -> list[Finding]:
    """检测「先拼接成变量，再交给 execute」的 SQL 注入。

    纯正则无法跨语句匹配，这里做一层轻量变量追踪：
    赋值右侧同时具备 SQL 关键词和拼接信号 → 追踪该变量是否流向 execute。
    误报率低于直接匹配 execute 调用，召回率高于单条正则。
    """
    findings: list[Finding] = []
    assigned: dict[str, tuple[int, str]] = {}

    for line_no, chunk in _logical_lines(text):
        m = ASSIGN_RE.match(chunk)
        if not m:
            continue
        var, rhs = m.group(1), m.group(2)
        if not SQL_KEYWORD_RE.search(rhs):
            continue
        if not CONCAT_SIGNAL_RE.search(rhs):
            continue
        # 参数化写法已在右侧显式分离，不算注入
        if re.search(r"(?i)\?\s*,\s*\(|%s\s*\)\s*,\s*\(|:\w+\s*,", rhs):
            continue
        assigned[var.split(".")[-1]] = (line_no, rhs)

    if not assigned:
        return findings

    for var, (line_no, rhs) in assigned.items():
        sink = re.search(
            rf"(?is)\b(?:execute|executemany|executescript|query|raw)\s*\(\s*{re.escape(var)}\s*[,)]",
            text,
        )
        if not sink:
            continue
        findings.append(
            Finding(
                rule_id="bee.sql-injection",
                severity=Severity.ERROR,
                message="SQL 注入（字符串拼接构造查询）",
                path=rel,
                start_line=line_no,
                end_line=line_no + rhs.count("\n"),
                cwe=["CWE-89"],
                owasp=["A03:2021"],
                references=["https://cwe.mitre.org/data/definitions/89.html"],
                snippet="\n".join(text.splitlines()[max(0, line_no - 3): line_no + 3]),
                detector="bee-flow",
                raw={
                    "title": "SQL 注入（字符串拼接构造查询）",
                    "root_cause_hint": (
                        f"变量 {var} 在拼接时把外部数据混入了 SQL 文本，"
                        f"数据库无法区分语句结构与数据，{var} 被直接交给 execute。"
                    ),
                    "fix_hint": "改为参数化查询：SQL 文本里只保留占位符，外部数据全部通过参数绑定传入。",
                    "matched": rhs[:400],
                    "dataflow": f"{rel}:{line_no} 拼接 -> execute({var})",
                },
            )
        )
    return findings


def _snippet(text: str, start_line: int, context: int = 0) -> str:
    lines = text.splitlines()
    lo = max(0, start_line - 1 - context)
    hi = min(len(lines), start_line + context)
    return "\n".join(lines[lo:hi])


COMMENT_PREFIXES = ("#", "//", "/*", "*", "*/", "--", "<!--")

# 判断「这一行是在定义正则 / 规则，而不是在写业务代码」。
# 没有这层过滤，任何带安全规则表的项目都会被自己的规则命中，
# 这是实测中最刺眼的误报来源。
REGEX_META_HINTS = ("\\s", "\\b", "\\w", "\\d", "(?:", "[^", "(?i", "(?s", "(?m", ".*?", "[\\")
RULE_DEF_HINTS = ("re.compile", "pattern=", "regex", "Regex", "regexp", "RegExp")


def _looks_like_rule_text(line: str) -> bool:
    meta_hits = sum(1 for hint in REGEX_META_HINTS if hint in line)
    if meta_hits >= 2:
        return True
    return any(hint in line for hint in RULE_DEF_HINTS)


def _is_comment_or_rule_line(lines: list[str], line_no: int) -> bool:
    if not (1 <= line_no <= len(lines)):
        return False
    stripped = lines[line_no - 1].lstrip()
    if stripped.startswith(COMMENT_PREFIXES):
        return True
    return _looks_like_rule_text(stripped)


def scan_file(path: Path, root: Path, rules: list[Rule] | None = None) -> list[Finding]:
    rules = rules if rules is not None else BUILTIN_RULES
    lang = detect_language(path)
    if not lang:
        return []
    try:
        text = read_source(path)
    except OSError:
        return []
    if not text.strip():
        return []

    rel = str(path.relative_to(root)).replace("\\", "/")
    source_lines = text.splitlines()
    findings: list[Finding] = []

    for rule in rules:
        if lang not in rule.languages:
            continue
        try:
            matches = list(re.finditer(rule.pattern, text))
        except re.error:
            continue
        if not matches:
            continue
        # require：整个文件必须至少命中一次才认为规则生效
        if rule.require and not any(re.search(r, text, re.I | re.S) for r in rule.require):
            continue

        seen_lines: set[int] = set()
        for m in matches:
            start_line = _line_of(text, m.start())
            if start_line in seen_lines:
                continue
            window = text[max(0, m.start() - 600): m.end() + 600]
            if rule.safe_when and any(re.search(s, window, re.I | re.S) for s in rule.safe_when):
                continue
            if _is_comment_or_rule_line(source_lines, start_line):
                continue
            # 参数化查询里，参数值自己做拼接是安全的：拼接发生在应用层，不进 SQL 文本
            if rule.id == "bee.sql-injection" and _is_parameterized_sql_call(text, m.start()):
                continue
            seen_lines.add(start_line)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.title,
                    path=rel,
                    start_line=start_line,
                    end_line=_line_of(text, max(m.end() - 1, m.start())),
                    cwe=list(rule.cwe),
                    owasp=list(rule.owasp),
                    references=list(rule.references),
                    snippet=_snippet(text, start_line, context=3),
                    detector="bee-rules",
                    raw={"title": rule.title, "root_cause_hint": rule.root_cause_hint,
                         "fix_hint": rule.fix_hint, "matched": m.group(0)[:400]},
                )
            )

    # 数据流补充检测：捕获「先拼接成变量、再交给 execute」这类正则跨不过去的写法
    if lang in {"python", "javascript", "typescript", "go", "java", "php"}:
        findings.extend(_detect_sql_flow(text, rel))

    # 同一规则在同一行的重复命中合并
    seen: set[tuple[str, int]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.start_line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


def scan_tree(
    root: Path,
    rules: list[Rule] | None = None,
    include_globs: list[str] | None = None,
    only_paths: list[str] | None = None,
) -> list[Finding]:
    targets = iter_source_files(root, include_globs)
    if only_paths:
        wanted = {p.replace("\\", "/") for p in only_paths}
        targets = [p for p in targets if str(p.relative_to(root)).replace("\\", "/") in wanted]

    findings: list[Finding] = []
    for f in targets:
        findings.extend(scan_file(f, root, rules))
    # 同文件同规则相邻行合并噪音
    findings.sort(key=lambda x: (x.path, x.start_line, x.rule_id))
    return findings


def load_custom_rules(path: Path) -> list[Rule]:
    """加载用户自定义规则：Python 文件里定义 RULES 列表。"""
    import importlib.util

    spec = importlib.util.spec_from_file_location("bee_custom_rules", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"无法加载规则文件: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rules = getattr(module, "RULES", None)
    if not isinstance(rules, list):
        raise ValueError(f"规则文件必须定义 RULES 列表: {path}")
    return rules

"""检测层：可插拔的规则引擎。

默认使用内置规则（零依赖、离线），也可通过 semgrep_backend 合并外部 semgrep
结果。内置规则自带 root_cause_hint / fix_hint，这是可解释性分析的先验知识，
比纯正则信号强得多。

设计取舍：宁可少而准。误报会摧毁可解释性修复的可信度，
因为你会花半页篇幅解释一个根本不存在的漏洞。
"""

from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .io_utils import read_source
from .models import Finding, Severity

# ---------------------------------------------------------------- 规则定义


class Confidence(str, Enum):
    """规则的判定把握度，决定它出现在哪个 --profile 档位。

    真实项目里误报的代价不是「多看一眼」，而是使用者直接关掉这条流水线。
    分档让「模式明确」和「启发式」分开：默认档只报有把握的。
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


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
    confidence: Confidence = Confidence.MEDIUM
    # 命中本来就该落在字符串字面量内部（PEM 私钥、云厂商密钥），
    # 这类规则不能被字符串过滤掉
    allow_in_strings: bool = False
    # 按语言覆盖 pattern：同一条规则在 Python 和 JS 里的危险写法完全不同，
    # 用一个正则硬套必然两个方向都错（Python 的 iscoroutinefunction 被 JS 的
    # Function( 分支命中，就是这个坑）
    pattern_by_lang: dict[str, str] = field(default_factory=dict)


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
        # 两条分支：join 系列，以及「绝对路径字面量 + 变量」的直接拼接
        # join 的第一个参数是 self.xxx 时跳过：那是对象内部目录（mailbox、
        # 缓存实现这类），不是外部可控根目录，这类是 stdlib 上 10 条误报的来源。
        pattern=r"""(?is)(?:(?:open|readFile|readFileSync|createReadStream|send_file|sendFile|ioutil\.ReadFile|os\.ReadFile|FileInputStream)\s*\(\s*(?:os\.path\.join|path\.join|filepath\.Join)\s*\(\s*(?!self\.)[^)]{0,200}\w[^)]{0,200}\)?|(?:open|readFile|readFileSync)\s*\(\s*f?["'][^"'\n]{0,160}/["']\s*\+)""",
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
        # 分隔符要同时支持 = 和 :，否则 YAML / JSON 配置里的 password: "xxx" 会漏掉。
        # 命名捕获组 (1)=变量名 (2)=引号 (3)=值：光靠正则判断不了「这是不是真凭据」，
        # 必须看值本身（token_type = 'unstructured' 那种必须排除）。
        pattern=r"""(?i)(?<![A-Za-z0-9])([A-Za-z0-9_.]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|credential)[A-Za-z0-9_]*)\s*(?<![=!<>])[:=](?!=)\s*(["'])([^"'\s]{6,})\2""",
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
        # 裸 eval(变量) 本身就是高危，不该要求它必须伴随字符串拼接。
        # 只排除 literal_eval 与无参的 model.eval()。
        # 基础 pattern 只覆盖 Python：原来的 |Function) 分支没有左边界，
        # 加上 (?is) 后 `iscoroutinefunction(`、`this_function(` 全部命中
        # ——这是 stdlib 上 175 条误报的主因。JS/PHP 各用自己的写法。
        pattern=r"""(?is)(?<![A-Za-z0-9_])(?:eval|exec|execfile)\s*\(""",
        pattern_by_lang={
            "javascript": r"""(?is)(?<![A-Za-z0-9_$])(?:eval|Function)\s*\(|(?<![A-Za-z0-9_$])new\s+Function\s*\(|setTimeout\s*\(\s*["'`]""",
            "typescript": r"""(?is)(?<![A-Za-z0-9_$])(?:eval|Function)\s*\(|(?<![A-Za-z0-9_$])new\s+Function\s*\(|setTimeout\s*\(\s*["'`]""",
            "php": r"""(?is)(?<![A-Za-z0-9_])(?:eval|create_function|assert)\s*\(""",
        },
        safe_when=[r"(?i)ast\.literal_eval|json\.parse|\.eval\s*\(\s*\)"],
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
        pattern=r"""(?is)\b(?:hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)|createHash\s*\(\s*["'](?:md5|sha1)|crypto\.(?:MD5|SHA1)|(?:md5|sha1)\.(?:New|Sum)|crypto\.createHash\s*\(\s*["']md5)""",
        safe_when=[
            # 显式声明非安全用途的哈希（Python 3.9+ 的标准做法），不该报。
            # 不用 "fingerprint" 这类词做窗口匹配——±600 字符窗口里出现一次
            # 就会压制真实命中，宁可窄不可宽。
            r"(?i)usedforsecurity\s*=\s*False",
        ],
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
        pattern=r"""(?is)(?:innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|\.html\s*\(\s*[^)\s]*(?:\+|\$\{))""",
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
        # CERT_NONE 只能出现在「赋值/传参」位置：`verify_mode != CERT_NONE`
        # 是正常校验逻辑，原来会误报（stdlib 的 ssl.py 就被打中）
        pattern=r"""(?is)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|TrustAllCerts|checkServerIdentity\s*:\s*\(\s*\)\s*=>|_create_unverified_context|(?:verify_mode|CERT_NONE)\s*=\s*(?:ssl\.)?CERT_NONE|check_hostname\s*=\s*False)""",
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
    # ---------------------------------------------------------- 第二批规则
    # 原则：宁可窄也不误报。误报会浪费一整轮 LLM 重试，还会让人不再信任报告。
    Rule(
        id="bee.dynamic-order-by",
        title="ORDER BY / 列名由外部输入决定（参数化无法防御）",
        severity=Severity.ERROR,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:\border\s+by\b[^;]{0,80}(?:\+\s*\w|\$\{|\{\w*\}|%s["']?\s*%|\|\|)|["']\s*\+\s*\w+\s*\+\s*["']\s*(?:asc|desc|limit))""",
        safe_when=[r"(?i)ORDER_BY_SAFE|allowed_sort|SAFE_COLUMNS|whitelist|allowlist"],
        # 命中点就在 SQL 字符串内部（"ORDER BY " + col），不能做字符串过滤
        allow_in_strings=True,
        root_cause_hint="列名和排序方向属于 SQL 语法结构，不能用参数占位符表达，一旦可被外部输入改变就等于把排序子句交给了攻击者。",
        fix_hint="用白名单映射：外部传入的字段名先查表，映射到固定的列名字面量，查不到就用默认列。",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    ),
    Rule(
        id="bee.ssti",
        title="服务端模板注入（SSTI）",
        severity=Severity.ERROR,
        cwe=["CWE-1336", "CWE-94"],
        owasp=["A03:2021"],
        languages=["python", "javascript", "typescript", "java", "php"],
        pattern=r"""(?is)(?:render_template_string\s*\(|jinja2\.Template\s*\(|\bTemplate\s*\(\s*(?:f["']|[^)\n]{0,120}(?:\+|%\s*\w|\$\{))|Environment\s*\(\s*\)\.from_string|nunjucks\.renderString|handlebars\.compile\s*\(|Twig.*?createTemplate)""",
        safe_when=[r"(?i)render_template\s*\(\s*[\"']|autoescape\s*=\s*True"],
        root_cause_hint="模板引擎会把内容当作代码解析，用户可控的模板字符串等于允许对方在服务端执行表达式。",
        fix_hint="渲染固定的模板文件，外部数据只作为上下文变量传入；确实需要动态模板时用沙箱环境并禁用危险过滤器。",
        references=["https://cwe.mitre.org/data/definitions/1336.html"],
    ),
    Rule(
        id="bee.nosql-injection",
        title="NoSQL 注入（请求数据直接进查询条件）",
        severity=Severity.ERROR,
        cwe=["CWE-943"],
        owasp=["A03:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)\b(?:find|find_one|findOne|update_one|updateOne|update_many|delete_one|deleteMany|aggregate)\s*\(\s*\{[^}]{0,240}(?:request\.(?:args|form|json|GET|POST)|req\.(?:body|query|params)|\$_GET|\$_POST)""",
        safe_when=[r"(?i)\$eq|\$in.*query|isinstance\(.*(?:str|int)\)|typeof\s+\w+\s*===\s*['\"]string"],
        root_cause_hint="把整个请求对象当作查询条件，攻击者可以塞入 $ne、$gt、$where 这类操作符改变查询语义，或触发服务端 JS 执行。",
        fix_hint="只取明确的标量字段并校验类型，构造查询条件时不要展开整个请求体；禁用 $where。",
        references=["https://cwe.mitre.org/data/definitions/943.html"],
    ),
    Rule(
        id="bee.open-redirect",
        title="开放重定向（跳转目标由外部输入决定）",
        severity=Severity.WARNING,
        cwe=["CWE-601"],
        owasp=["A01:2021"],
        languages=["python", "javascript", "typescript", "java", "php"],
        pattern=r"""(?is)(?:\bredirect\s*\(\s*(?:request\.(?:args|form|values|GET)|req\.(?:query|body|params)|params\[|\$_GET)|sendRedirect\s*\(\s*(?:request\.|params)|res\.redirect\s*\(\s*(?:req\.|request\.))""",
        safe_when=[r"(?i)allowed_hosts|ALLOWED_REDIRECT|url_has_allowed_host_and_scheme|is_safe_url|startswith\(\s*['\"]/['\"]"],
        root_cause_hint="跳转目标直接取自请求参数，攻击者可以把链接伪装成你的域名，把用户导向钓鱼页。",
        fix_hint="只允许站内相对路径，或用白名单校验目标域名；Django 用 url_has_allowed_host_and_scheme。",
        references=["https://cwe.mitre.org/data/definitions/601.html"],
    ),
    Rule(
        id="bee.csrf-disabled",
        title="CSRF 保护被关闭",
        severity=Severity.WARNING,
        cwe=["CWE-352"],
        owasp=["A01:2021"],
        languages=["python", "javascript", "typescript", "java", "php"],
        pattern=r"""(?is)(?:@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf_protect\s*=\s*False|\.csrf\s*\(\s*\)\s*\.disable|csrf\s*\(\s*\)\s*\.disable|csrf:\s*false|CsrfViewMiddleware)""",
        safe_when=[r"(?i)csrf_token|X-CSRF-Token|SameSite=Lax|SameSite=Strict"],
        root_cause_hint="关闭 CSRF 校验后，第三方站点可以借用户已登录的 Cookie 发起跨站请求，执行用户没打算做的操作。",
        fix_hint="保留框架默认的 CSRF 保护；确实需要豁免的接口改用 Token 认证或校验 Origin/Referer。",
        references=["https://cwe.mitre.org/data/definitions/352.html"],
    ),
    Rule(
        id="bee.cors-wildcard",
        title="CORS 允许任意来源",
        severity=Severity.WARNING,
        cwe=["CWE-942"],
        owasp=["A05:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*["']|origin\s*:\s*["']\*["']|addAllowedOrigin\s*\(\s*["']\*["']|CORS_ORIGIN_ALLOW_ALL\s*=\s*True)""",
        safe_when=[r"(?i)allow_credentials\s*[:=]\s*(?:False|false)|supports_credentials\s*=\s*False"],
        root_cause_hint="通配来源让任何站点都能读取接口响应；如果同时允许携带 Cookie，等于把登录态借给了任意第三方页面。",
        fix_hint="改为固定来源白名单；绝不能同时开启 allow_credentials 与通配来源。",
        references=["https://cwe.mitre.org/data/definitions/942.html"],
    ),
    Rule(
        id="bee.jwt-verify-disabled",
        title="JWT 签名校验被关闭",
        severity=Severity.ERROR,
        cwe=["CWE-347"],
        owasp=["A02:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:verify_signature["']?\s*[:=]\s*(?:False|false)|jwt\.decode\s*\([^)]{0,200}verify\s*=\s*False|JWT\.decode\s*\([^)]{0,200}verify\s*=\s*False|algorithms?\s*[:=]\s*\[\s*["']none["']|\.setSigningKey\s*\(\s*["']["']\s*\))""",
        safe_when=[r"(?i)algorithms?\s*=\s*\[\s*[\"'](?:RS256|HS256|ES256)"],
        root_cause_hint="不校验签名时，任何人都能自己造一个包含任意身份的 JWT，鉴权形同虚设。",
        fix_hint="强制校验签名并显式指定允许的算法（如 RS256），拒绝 none 算法。",
        references=["https://cwe.mitre.org/data/definitions/347.html"],
    ),
    Rule(
        id="bee.redos",
        title="正则表达式拒绝服务（嵌套量词）",
        severity=Severity.WARNING,
        cwe=["CWE-1333"],
        owasp=["A05:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)\b(?:re\.(?:compile|match|search|fullmatch|sub)|new\s+RegExp|RegExp\s*\()\s*\(?\s*["'][^"'\n]{0,200}(?:\([^)\n]{0,40}[+*]\)[+*]|\.\*[^"']{0,40}\.\*|\[[^\]]{0,40}\][+*][^\n]{0,10}[+*])""",
        safe_when=[r"(?i)re2|RE2|re\.escape|timeout\s*="],
        root_cause_hint="嵌套或重叠量词会让回溯时间随输入长度指数增长，攻击者用一个精心构造的长字符串就能占满 CPU。",
        fix_hint="改写正则消除歧义（避免 (a+)+ 这类结构），或改用 RE2 这类无回溯引擎，并给匹配设置超时。",
        references=["https://cwe.mitre.org/data/definitions/1333.html"],
    ),
    Rule(
        id="bee.zip-slip",
        title="压缩包解压未校验路径（Zip Slip）",
        severity=Severity.ERROR,
        cwe=["CWE-22"],
        owasp=["A01:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        # tarfile.open 只是打开，不是解压，原来把它算进来纯属噪音；
        # 解压侧要认 extractall / extract(member=...)，以及 3.12 起的 filter= 修复。
        pattern=r"""(?is)(?:\.extractall\s*\(|\.extract\s*\(\s*[^)\n]{0,100}(?:member|name|filename|entry)|tarfile\.extractall|ZipFile\s*\([^)]*\)\s*\.\s*extract)""",
        safe_when=[
            r"(?i)realpath|commonpath|is_relative_to|secure_|basename|resolve\(\).*startswith",
            r"(?i)extractall\s*\([^)]*\bfilter\s*=",  # 3.12+ 的 filter="data"
        ],
        root_cause_hint="压缩包内的条目名可以包含 ../，直接解压会把文件写到目标目录之外，覆盖任意可写路径。",
        fix_hint="解压前把条目的规范化绝对路径与目标根目录做前缀比较，越界就拒绝。",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
    ),
    Rule(
        id="bee.private-key-hardcoded",
        title="私钥硬编码在源码中",
        severity=Severity.ERROR,
        cwe=["CWE-321"],
        owasp=["A02:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php", "yaml", "json", "env"],
        pattern=r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----""",
        safe_when=[r"(?i)test|example|dummy|fixture|sample"],
        root_cause_hint="私钥随源码进入版本库和镜像，任何拿到代码的人都能签发或解密，且轮换成本极高。",
        fix_hint="把私钥移到密钥管理服务或部署时挂载的文件，源码里只留路径；同时在密钥系统里轮换这把已泄露的私钥。",
        references=["https://cwe.mitre.org/data/definitions/321.html"],
    ),
    Rule(
        id="bee.cloud-credential",
        title="云平台访问密钥硬编码",
        severity=Severity.ERROR,
        cwe=["CWE-798"],
        owasp=["A07:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php", "yaml", "json", "env"],
        pattern=r"""(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])""",
        safe_when=[r"(?i)example|dummy|test|sample|xxx|AKIAIOSFODNN7EXAMPLE"],
        root_cause_hint="长期访问密钥写死在代码里，泄露后攻击者可直接以该 IAM 身份操作云资源，且默认不会过期。",
        fix_hint="改用实例角色或 OIDC 临时凭证；如果这是真实密钥，先在云平台禁用它再改代码。",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    Rule(
        id="bee.sensitive-data-logging",
        title="敏感字段被写入日志",
        severity=Severity.WARNING,
        cwe=["CWE-532"],
        owasp=["A09:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:logger?\.(?:info|warning|error|debug|critical|exception)|log\.(?:info|warn|error|debug)|console\.log|print)\s*\([^)\n]{0,200}\b(?:password|passwd|secret|token|api_?key|credential|private_key|card_?number|ssn)\b""",
        safe_when=[r"(?i)mask|redact|\*\*\*|hash|fingerprint|last4|\[REDACTED\]"],
        root_cause_hint="日志会被采集到集中平台，访问权限通常远大于业务数据本身，凭据一旦进日志就等于扩大了泄露面。",
        fix_hint="记录前脱敏（只留后四位或哈希），或直接不打敏感字段。",
        references=["https://cwe.mitre.org/data/definitions/532.html"],
    ),
    Rule(
        id="bee.insecure-cookie",
        title="Cookie 缺少安全属性",
        severity=Severity.WARNING,
        cwe=["CWE-614", "CWE-1004"],
        owasp=["A05:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:set_cookie\s*\([^)\n]{0,300}(?:httponly\s*=\s*False|secure\s*=\s*False|samesite\s*=\s*["']?none)|res\.cookie\s*\([^)\n]{0,300}(?:httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*["']none))""",
        safe_when=[],
        root_cause_hint="缺少 HttpOnly 时脚本能读到 Cookie，缺少 Secure 时明文请求也会带上它，SameSite=None 则允许跨站携带。",
        fix_hint="会话 Cookie 一律 HttpOnly + Secure + SameSite=Lax（或 Strict）。",
        references=["https://cwe.mitre.org/data/definitions/614.html"],
    ),
    Rule(
        id="bee.unrestricted-upload",
        title="文件上传未限制类型与路径",
        severity=Severity.WARNING,
        cwe=["CWE-434"],
        owasp=["A04:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        pattern=r"""(?is)(?:\.save\s*\(\s*(?:os\.path\.join\s*\([^)]{0,120}(?:filename|request\.files|file\.name)|request\.files\[[^\]]*\]\[?["']?filename)|move_uploaded_file\s*\(|transferTo\s*\()""",
        safe_when=[r"(?i)secure_filename|ALLOWED_EXT|allowed_extensions|mimetype.*in|content_type.*in"],
        root_cause_hint="直接使用客户端提供的文件名和类型，攻击者可以上传可执行脚本到 Web 可访问目录，进而拿到服务器权限。",
        fix_hint="用服务端生成的文件名，白名单校验扩展名与 MIME，把上传目录放到 Web 根目录之外。",
        references=["https://cwe.mitre.org/data/definitions/434.html"],
    ),
    Rule(
        id="bee.prototype-pollution",
        title="原型链污染（外部数据合并进对象）",
        severity=Severity.ERROR,
        cwe=["CWE-1321"],
        owasp=["A08:2021"],
        languages=["javascript", "typescript"],
        pattern=r"""(?is)(?:\[["']__proto__["']\]|\.__proto__\s*=(?!=)|\b(?:merge|extend|defaultsDeep|deepMerge)\s*\(\s*\{\s*\}\s*,\s*(?:req\.|request\.|body)|Object\.assign\s*\(\s*[\w.]+\s*,\s*(?:req\.|request\.))""",
        safe_when=[r"(?i)Object\.create\(null\)|hasOwnProperty|__proto__.*delete|JSON\.parse\(JSON\.stringify"],
        root_cause_hint="递归合并时把 __proto__ 当成普通属性写入，会污染所有对象的原型，影响整个进程后续逻辑。",
        fix_hint="合并前剔除 __proto__ / constructor / prototype 键，或用 Object.create(null) 作为目标对象。",
        references=["https://cwe.mitre.org/data/definitions/1321.html"],
    ),
    Rule(
        id="bee.timing-attack",
        title="凭据比较未使用恒定时间算法",
        severity=Severity.INFO,
        cwe=["CWE-208"],
        owasp=["A02:2021"],
        languages=["python", "javascript", "typescript", "go", "java", "php"],
        # 去掉 token：歧义太大，`tokenL == 0xF` 这类比较会被误判。
        # 并且排除右侧是数字字面量的比较（那不是凭据比对）。
        # 关键词允许出现在标识符任意位置（expected_signature 也要报），
        # 但去掉 token 这个歧义太大的词，并排除与数字字面量比较
        pattern=r"""(?is)\bif\s+[\w.]*(?:password|passwd|secret|hmac|digest|signature|api[_-]?key)[\w.]*\s*==\s*(?![\d.])[\w.]+""",
        safe_when=[r"(?i)compare_digest|timingSafeEqual|constant_time|hmac\.compare|secrets\.compare|crypto\.timingSafeEqual"],
        root_cause_hint="字符串 == 会在首个不同字节处提前返回，攻击者可以通过响应时间差逐字节推断出正确值。",
        fix_hint="改用 hmac.compare_digest / crypto.timingSafeEqual 这类恒定时间比较。",
        references=["https://cwe.mitre.org/data/definitions/208.html"],
    ),
    Rule(
        id="bee.ldap-injection",
        title="LDAP 过滤器注入",
        severity=Severity.ERROR,
        cwe=["CWE-90"],
        owasp=["A03:2021"],
        languages=["python", "javascript", "typescript", "java", "php"],
        pattern=r"""(?is)(?:search_filter\s*=\s*["'][^"']{0,160}\(\s*\w+\s*=\s*["']\s*\+|\bfilter\s*=\s*f["'][^"']{0,160}\(\s*\w+\s*=\s*\{|\(\s*uid\s*=\s*["']\s*\+)""",
        safe_when=[r"(?i)escape_filter_chars|ldap_filter_escape|filter_format|re\.escape"],
        root_cause_hint="LDAP 过滤器的元字符（* ( ) \\ |）没有转义，攻击者能改变过滤条件，绕过认证或枚举整个目录。",
        fix_hint="对插入值做 RFC 4515 转义（escape_filter_chars / ldap_escape），不要拼接原始输入。",
        references=["https://cwe.mitre.org/data/definitions/90.html"],
    ),
    Rule(
        id="bee.xxe",
        title="XML 外部实体注入（XXE）",
        severity=Severity.ERROR,
        cwe=["CWE-611"],
        owasp=["A05:2021"],
        languages=["python", "javascript", "typescript", "java", "php"],
        # 三条分支：Python 的 XMLParser / lxml 解析、Java 的 DocumentBuilderFactory、
        # PHP 的 libxml 相关开关与直接 loadXML
        pattern=r"""(?is)(?:\b(?:etree\.XMLParser|XMLParser|lxml\.etree\.(?:fromstring|parse)|xml\.dom\.minidom\.parse(?:String)?)\s*\(|DocumentBuilderFactory\.newInstance\s*\(\s*\)|libxml_disable_entity_loader\s*\(\s*(?:false|0)\s*\)|setFeature\s*\(\s*["'][^"']*disallow-doctype-decl[^"']*["']\s*,\s*false\s*\)|(?:simplexml_load_string|DOMDocument\s*->\s*loadXML)\s*\()""",
        safe_when=[
            r"(?i)resolve_entities\s*=\s*False|no_network\s*=\s*True|forbid_dtd\s*=\s*True",
            r"(?i)defusedxml|defused",
            r"(?i)setFeature\s*\(\s*[\"'][^\"']*disallow-doctype-decl[^\"']*[\"']\s*,\s*true\s*\)|setFeature\s*\(\s*[\"'][^\"']*external-general-entities[^\"']*[\"']\s*,\s*false\s*\)",
            r"(?i)LIBXML_NONET|LIBXML_NOENT\s*\|\s*LIBXML_NONET",
            r"(?i)libxml_disable_entity_loader\s*\(\s*(?:true|1)\s*\)",
        ],
        root_cause_hint="XML 解析器默认允许 DTD 与外部实体，攻击者可以用 SYSTEM 实体读取本地文件、发起 SSRF 或造成拒绝服务（实体膨胀）。",
        fix_hint="禁用 DTD 与外部实体：Python 用 defusedxml 或 XMLParser(resolve_entities=False, no_network=True)；Java 给 DocumentBuilderFactory 设置 disallow-doctype-decl=true 并关闭 external entities；PHP 解析时加 LIBXML_NONET 且不开 LIBXML_NOENT。",
        references=["https://cwe.mitre.org/data/definitions/611.html"],
    ),
)


# ---------------------------------------------------------------- 规则分级

# 把握度按「误报面」定，不按危害定：危害决定 severity，把握度决定默认报不报。
# 新增规则必须在这里登记，否则 test_rules_have_confidence 会失败——避免新规则
# 悄悄以 MEDIUM 混进默认档。
_CONFIDENCE_BY_ID: dict[str, Confidence] = {
    # 模式明确、几乎没有别的解释
    "bee.sql-injection": Confidence.HIGH,
    "bee.command-injection": Confidence.HIGH,
    "bee.unsafe-deserialization": Confidence.HIGH,
    "bee.path-traversal": Confidence.HIGH,
    "bee.zip-slip": Confidence.HIGH,
    "bee.xxe": Confidence.HIGH,
    "bee.jwt-verify-disabled": Confidence.HIGH,
    "bee.prototype-pollution": Confidence.HIGH,
    "bee.private-key-hardcoded": Confidence.HIGH,
    "bee.cloud-credential": Confidence.HIGH,
    "bee.code-injection": Confidence.HIGH,
    "bee.nosql-injection": Confidence.HIGH,
    "bee.ssti": Confidence.HIGH,
    "bee.ldap-injection": Confidence.HIGH,
    "bee.dynamic-order-by": Confidence.HIGH,
    # 需要看上下文才能确认
    "bee.hardcoded-credential": Confidence.MEDIUM,
    "bee.weak-crypto": Confidence.MEDIUM,
    "bee.xss": Confidence.MEDIUM,
    "bee.ssrf": Confidence.MEDIUM,
    "bee.tls-verify-disabled": Confidence.MEDIUM,
    "bee.insecure-cookie": Confidence.MEDIUM,
    "bee.unrestricted-upload": Confidence.MEDIUM,
    # 启发式，只在 full 档报
    "bee.insecure-random": Confidence.LOW,
    "bee.timing-attack": Confidence.LOW,
    "bee.debug-enabled": Confidence.LOW,
    "bee.csrf-disabled": Confidence.LOW,
    "bee.cors-wildcard": Confidence.LOW,
    "bee.open-redirect": Confidence.LOW,
    "bee.sensitive-data-logging": Confidence.LOW,
    "bee.redos": Confidence.LOW,
}

# 命中天然落在字符串内部的规则：PEM 私钥、AKIA/云厂商密钥本身就是字符串常量，
# 被字符串过滤掉就永远报不出来。
_ALLOW_IN_STRINGS = {"bee.private-key-hardcoded", "bee.cloud-credential"}

for _rule in BUILTIN_RULES:
    if _rule.id in _CONFIDENCE_BY_ID:
        _rule.confidence = _CONFIDENCE_BY_ID[_rule.id]
    # 只加不减：规则自己声明了 allow_in_strings=True 的（如 dynamic-order-by）
    # 不能被这张表覆盖掉
    if _rule.id in _ALLOW_IN_STRINGS:
        _rule.allow_in_strings = True


# ---------------------------------------------------------------- 误报抑制启发式

# token_type / api_key_name / secret_len 这类名字里的关键词只是名字的一部分，
# 值也不是密钥。凭据规则的 recall 从来不缺，缺的是 precision。
_WEAK_NAME_SUFFIX = (
    "_type", "_name", "_len", "_length", "_count", "_size", "_kind",
    "_label", "_text", "_mode", "_status", "_limit", "_field", "_path",
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)example|dummy|sample|placeholder|change.?me|your|xxx+|\*\*\*|redacted|<[^>]+>|\$\{"
)


def looks_like_secret(name: str, value: str) -> bool:
    """判断「名字像凭据 + 值像密钥」是否真的成立。

    三道门：名字不是 *_type 这类元信息、值不是占位符、值足够长且字符种类够杂。
    单靠宽松正则会把 `token_type = 'unstructured'` 当成密钥——
    stdlib 上 44 条里几乎全是这一类。
    """
    if name.lower().endswith(_WEAK_NAME_SUFFIX):
        return False
    if _PLACEHOLDER_RE.search(value):
        return False
    if len(value) < 12:
        return False
    classes = sum(
        1 for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
        if re.search(pattern, value)
    )
    return classes >= 2


# ---------------------------------------------------------------- 字符串/注释区间

def _line_offsets(text: str) -> list[int]:
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _string_spans_python(text: str) -> list[tuple[int, int]]:
    """用 tokenize 取 Python 的 STRING/COMMENT 区间（能正确处理三引号与转义）。"""
    spans: list[tuple[int, int]] = []
    offsets = _line_offsets(text)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                start = offsets[tok.start[0] - 1] + tok.start[1]
                end = offsets[tok.end[0] - 1] + tok.end[1]
                spans.append((start, end))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    return spans


def _string_spans_generic(text: str) -> list[tuple[int, int]]:
    """其它语言的轻量扫描：引号字符串 + // 与 /* */ 注释。

    不追求完备（模板字符串嵌套之类会漏），目标是把「文档里的示例代码」
    这类噪音挡掉，漏判方向是宁可多报。
    """
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            spans.append((i, j))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            spans.append((i, j))
            i = j
        elif text[i] in "\"'`":
            quote, j = text[i], i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                if text[j] == "\n" and quote != "`":
                    # 未闭合的引号：当成到行尾，避免把整个文件吞掉
                    j += 1
                    break
                j += 1
            spans.append((i, j))
            i = j
        else:
            i += 1
    return spans


def _string_spans(text: str, lang: str) -> list[tuple[int, int]]:
    if lang == "python":
        return _string_spans_python(text)
    return _string_spans_generic(text)


def _inside(index: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= index < end for start, end in spans)


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

# bee 自己产出的文件不该被下一轮扫描：基线和 SARIF 里含被命中的代码片段，
# 扫它们既制造噪音，也可能把敏感片段再报一遍。
SKIP_FILENAMES = {".bee-baseline.json"}

MAX_FILE_BYTES = 800_000

_GLOB_CACHE: dict[str, re.Pattern] = {}


def glob_to_regex(pattern: str) -> re.Pattern:
    """把 glob 转成正则，**正确处理 `**`**。

    fnmatch 的 `*` 会跨过 `/`，`Path.match` 又不支持递归 `**`，
    所以 `tests/**`、`src/**/*.py` 这两种最常用写法在它们手上都会失效。
    这里统一语义：
      `*`   → 不跨目录的任意字符
      `**`  → 跨目录的任意字符（`**/` 可以匹配零层目录）
      `?`   → 单个非 `/` 字符
    """
    if pattern in _GLOB_CACHE:
        return _GLOB_CACHE[pattern]
    pat = pattern.replace("\\", "/").lstrip("./")
    out: list[str] = []
    i = 0
    while i < len(pat):
        ch = pat[i]
        if ch == "*":
            if pat.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            elif pat.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    compiled = re.compile("^" + "".join(out) + "$")
    _GLOB_CACHE[pattern] = compiled
    return compiled


def matches_globs(rel_path: str, patterns: list[str] | None) -> bool:
    """rel_path 用 / 分隔的相对路径，判断是否命中任一 glob。"""
    if not patterns:
        return False
    rel = rel_path.replace("\\", "/").lstrip("./")
    return any(glob_to_regex(g).match(rel) for g in patterns if g and g.strip())


def detect_language(path: Path) -> str:
    if path.name == ".env" or path.suffix == ".env":
        return "env"
    return EXT_LANG.get(path.suffix.lower(), "")


def iter_source_files(
    root: Path,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
) -> list[Path]:
    """枚举待扫描文件。

    SKIP_DIRS 必须按**相对 root 的路径**判断。用绝对路径判断会把
    「目标本身就在某个被跳过的名字下」的情况整棵树灭掉——
    例如目标解析后落在 .../vendor/python/Lib，`vendor` 命中 SKIP_DIRS，
    结果 0 个文件却报告「无问题」。这比误报严重得多。
    """
    root = root.resolve()
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            rel_parts = p.relative_to(root).parts
        except ValueError:
            rel_parts = p.parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if p.name in SKIP_FILENAMES or p.suffix.lower() == ".sarif":
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if not detect_language(p):
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        if include_globs and not matches_globs(rel, include_globs):
            continue
        if exclude_globs and matches_globs(rel, exclude_globs):
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
# 字符串被外部数据拼接/插值的信号。PHP 用 . 拼接，不能只认 +
CONCAT_SIGNAL_RE = re.compile(
    r"""(?:["'`]\s*\+\s*\w)|(?:\w\s*\+\s*["'`])|(?:%\s*[\(\w])|(?:\.format\s*\()|(?:\bf["'])|(?:\$\{)|(?:["'`]\s*\.\s*\$)|(?:["'`]\s*\.\s*\(?\$?[A-Za-z_]\w*\s*\()"""
)
# 单行赋值。不用 re.S：逻辑行内部可能包含整段函数体，
# 用 .+ 跨行会把后续语句一起吞进 rhs，反而误判拼接信号。
ASSIGN_RE = re.compile(
    r"(?m)^[ \t]*(?:my\s+)?([$@]?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*=[ \t]*([^\n]*)"
)


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
    # 安全标识符：来自字典查找（TABLES[key]）或纯字符串常量（"orders"）的变量。
    # SQL 文本里只插值这种标识符 + 用户数据走占位符，是参数化查询的标准补法。
    safe_idents: set[str] = set()

    def _is_safe_ident_rhs(rhs: str) -> bool:
        r = rhs.strip()
        if re.match(r"""^["'][^"'{}]*["']$""", r):
            return True  # 纯字符串常量
        # 映射查找只认常量风格名字（TABLES[key] / {"a":"b"}[k]）：
        # request.args["table"] 同样是下标访问，但那是用户输入，不能当白名单。
        if re.match(r"^(?:[A-Z_][A-Z0-9_]*|\{.*\})\s*\[", r):
            return True
        return False

    for line_no, chunk in _logical_lines(text):
        for m in ASSIGN_RE.finditer(chunk):
            var, rhs = m.group(1), m.group(2)
            name = var.split(".")[-1]
            if _is_safe_ident_rhs(rhs):
                safe_idents.add(name)
            actual_line = line_no + chunk.count("\n", 0, m.start())
            if not SQL_KEYWORD_RE.search(rhs):
                continue
            if not CONCAT_SIGNAL_RE.search(rhs):
                continue
            # 参数化写法已在右侧显式分离，不算注入
            if re.search(r"(?i)\?\s*,\s*\(|%s\s*\)\s*,\s*\(|:\w+\s*,", rhs):
                continue
            assigned[name] = (actual_line, rhs)

    if not assigned:
        return findings

    for var, (line_no, rhs) in assigned.items():
        # 不用 \b：mysqli_query / db.query 里 query 前是下划线或点，
        # \b 在 _ 和 q 之间不成立，会整条漏掉
        sink = re.search(
            rf"(?is)(?<![A-Za-z0-9])(?:execute|executemany|executescript|query|raw)\s*\([^;]{{0,240}}?"
            rf"(?<![A-Za-z0-9_]){re.escape(var)}(?![A-Za-z0-9_])",
            text,
        )
        if not sink:
            continue
        # 汇点是参数绑定（execute(sql, params)）且 SQL 文本里的插值全部来自
        # 安全标识符（字典查找/常量）时不算注入。反例——
        # f"... '{name}' ... ?" + params 依然是注入，name 不在 safe_idents 里就继续报。
        open_idx = text.find("(", sink.start())
        interpolations = set(re.findall(r"\{(\w+)", rhs))
        if (
            len(_split_call_args(text, open_idx)) >= 2
            and interpolations
            and interpolations <= safe_idents
        ):
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
                code_line=(
                    text.splitlines()[line_no - 1].strip()
                    if 0 < line_no <= len(text.splitlines()) else ""
                ),
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
    # 每个文件只算一次字符串/注释区间：文档和测试里的示例代码是最大噪音源
    # （stdlib 上 46% 的命中落在 STRING token 里）
    spans = _string_spans(text, lang)

    for rule in rules:
        if lang not in rule.languages:
            continue
        pattern = rule.pattern_by_lang.get(lang, rule.pattern)
        if not pattern:
            continue
        try:
            matches = list(re.finditer(pattern, text))
        except re.error:
            continue
        if not matches:
            continue
        # require：整个文件必须至少命中一次才认为规则生效
        if rule.require and not any(re.search(r, text, re.I | re.S) for r in rule.require):
            continue

        seen_lines: set[int] = set()
        for m in matches:
            if not rule.allow_in_strings and _inside(m.start(), spans):
                continue
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
            # 凭据规则必须再看一眼名字与值：正则只负责找到「像赋值」的地方
            if rule.id == "bee.hardcoded-credential" and m.lastindex and m.lastindex >= 3:
                if not looks_like_secret(m.group(1), m.group(3)):
                    continue
            seen_lines.add(start_line)
            code_line = source_lines[start_line - 1].strip() if 0 < start_line <= len(source_lines) else ""
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
                    code_line=code_line,
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
    exclude_globs: list[str] | None = None,
) -> list[Finding]:
    # iter_source_files 内部会 resolve；这里同步一次，否则符号链接目录下
    # scan_file 里的 relative_to 会直接抛 ValueError
    root = root.resolve()
    targets = iter_source_files(root, include_globs, exclude_globs)
    if only_paths:
        wanted = {p.replace("\\", "/") for p in only_paths}
        targets = [p for p in targets if str(p.relative_to(root)).replace("\\", "/") in wanted]

    findings: list[Finding] = []
    for f in targets:
        findings.extend(scan_file(f, root, rules))
    # 按文件/行号/规则排序，保证输出稳定（不做跨行合并）
    findings.sort(key=lambda x: (x.path, x.start_line, x.rule_id))
    return findings


def merge_findings(primary: list[Finding], secondary: list[Finding]) -> list[Finding]:
    """合并两个后端的检测结果。

    同一「文件 + 行号 + 规则」两个后端都报了，只留一条：优先严重级别高的，
    同级时优先保留带污点路径的（信息更多，可解释性更好）。
    注意必须带规则名去重：同一行完全可能同时存在两种漏洞
    （例如一行里既有拼接 SQL 又有硬编码凭据），按位置去重会丢掉其中一种。
    """
    rank = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}
    best: dict[tuple[str, int, str], Finding] = {}

    for finding in list(primary) + list(secondary):
        key = (finding.path, finding.start_line, finding.rule_id)
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        if rank[finding.severity] > rank[current.severity]:
            best[key] = finding
        elif rank[finding.severity] == rank[current.severity] and finding.trace and not current.trace:
            best[key] = finding

    return sorted(best.values(), key=lambda x: (x.path, x.start_line, x.rule_id))


def load_custom_rules(path: Path) -> list[Rule]:
    """加载用户自定义规则：Python 文件里定义 RULES 列表。

    安全提示：这会**执行该文件的 Python 代码**（import 语义），
    与 `python your_rules.py` 等价。只加载自己写的规则文件，
    不要加载第三方仓库里附带的、未审阅的规则文件。
    """
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

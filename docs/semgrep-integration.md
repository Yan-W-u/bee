# 接 Semgrep / CodeQL：把 bee 当修复层用

bee 内置 30 条规则，覆盖面不如 Semgrep 的几千条，也不如 CodeQL 的跨过程分析。
与其硬拼检测，不如让专业工具做检测，bee 只做它们不做的事：**解释 + 补丁 + 机器验证**。

## 一条命令跑通

```bash
semgrep --sarif --config auto -o semgrep.sarif ./your-project
bee fix --input semgrep.sarif ./your-project
```

`--input` 存在时会**完全跳过**内置检测，finding 全部来自 SARIF。

CodeQL 同理：

```bash
codeql database analyze db codeql/python-queries --format=sarif-latest -o codeql.sarif
bee audit --input codeql.sarif ./your-project
```

## 已验证能解析的字段

| SARIF 字段 | 映射到 |
| --- | --- |
| `runs[].results[].ruleId` | `Finding.rule_id` |
| `message.text` | 报告标题 |
| `locations[0].physicalLocation.artifactLocation.uri` | 文件路径（相对项目根） |
| `region.startLine` / `endLine` | 行号 |
| `level`（缺省时回退到规则 `defaultConfiguration.level`） | 严重级别 |
| `properties.cwe` | CWE 标签 |

去重键是 `(path, start_line, rule_id)`——多 run 或多结果重复上报很常见。

## 重要限制：`finding_gone` 对 SARIF finding 是 `None`

四项验证信号里，`finding_gone` 靠「用同一条规则重扫」实现。外部规则的 id
在 bee 里不存在，重扫只会得到空结果，那会被误读成「已修复」——比不验证更危险。

所以外部 finding 的 `finding_gone` 记为 `None`，报告里标注：

> finding 来自外部 SARIF，本地没有可重扫的同名规则，未做「漏洞消失」验证

此时 `succeeded` 不会为真（它要求 `finding_gone is True`），也就是说
**`--input` 模式下不会有「已验证修复」的补丁**，只会产出未验证的 diff 供人 review。

这是当前版本的明确取舍。要拿到完整验证，三条路：

1. 用 bee 内置规则跑（有对应规则才能重扫）
2. 写一条等价的自定义规则放进 `--rules-file`，让 bee 能重扫（推荐）
3. 等后续版本实现「SARIF 规则回灌」

## 自定义规则补上重扫能力

```python
# my_rules.py —— 与 Semgrep 规则等价的最小实现
from bee.detect import Rule
from bee.models import Severity

RULES = [
    Rule(
        id="semgrep.python.lang.security.audit.formatted-sql-query",
        title="SQL 注入（字符串拼接构造查询）",
        severity=Severity.ERROR,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        languages=["python"],
        pattern=r"""(?is)execute\s*\(\s*f["'][^;]*?select[^;]*?\{""",
    ),
]
```

规则 id 与 SARIF 的 `ruleId` 保持一致，bee 就能重扫、就能给出真实的 `finding_gone`：

```bash
bee fix --input semgrep.sarif --rules-file my_rules.py ./your-project
```

## 为什么这比「自己扩规则」划算

- Semgrep 社区规则随 CVE 更新，你不需要追
- 报告里的「可解释性 + 机器验证」是 Semgrep 不做的部分，这部分才是差异
- 检测层越弱，越该把精力放在「接住别人的结果」而不是「再造一个更差的扫描器」

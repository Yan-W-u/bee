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
| `properties.cwe`（result 级） | CWE 标签 |
| `rules[].properties.tags`（规则级） | CWE / OWASP —— `CWE-89: …` 与 `external/cwe/cwe-089` 两种写法都归一 |
| `rules[].helpUri`（或 result 级） | 报告里的参考链接 |

去重键是 `(path, start_line, rule_id)`——多 run 或多结果重复上报很常见。

## 验证闭环：能不能证明「漏洞真的消失了」

四项验证信号里，`finding_gone` 靠「用同一条规则重扫」实现。外部规则的 id 在 bee
里不存在，硬重扫只会得到空结果，那会被误读成「已修复」——比不验证更危险。

所以 bee 对每条外部 finding 先做**映射**，映射成功才允许重扫：

| 来源 | 处理 |
| --- | --- |
| `py/sql-injection`、`python.lang.security.audit.formatted-sql-query` 等约 50 条 | `bee/aliases.py` 里人工核对过的表，**默认自动映射** |
| 你自己写的规则（id 与外部 `ruleId` 相同） | `--rescan-rules my_rules.py` 合并进来即可 |
| 其余 | 不映射，`finding_gone` 保持 `None`，报告只写「仅解释」 |

映射刻意保守：猜错方向会让结论反着来（拿 SQL 注入规则去判一个 XSS finding 是否消失）。
拿不准的宁可标「未验证」，也不冒充已验证。

```bash
# 自动映射覆盖的高频规则，直接用
bee fix --input semgrep.sarif ./your-project

# 自建规则：id 与 SARIF 的 ruleId 一致，就能被用来重扫
bee fix --input semgrep.sarif --rescan-rules my_rules.py ./your-project
```

跑起来会看到这样的提示，说明哪些条目进入了验证流程：

```
检测后端：外部 SARIF：semgrep.sarif（12 条）
检测后端：9 条已映射到本地规则，可验证「漏洞消失」
检测后端：3 条无本地等价规则（acme.custom-check…）→ 只做解释，不声称已验证
```

映射不上的条目**不会**出现「已验证修复」，只会产出未验证的 diff 供人 review。
`--rescan-rules` 与 `--rules-file` 的区别：前者是「在内置规则之上追加」，
后者是「完全替换内置规则」。只想补重扫能力时用前者。

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

规则 `id` 与 SARIF 的 `ruleId` 逐字相同，映射就自动成立（不需要往
`aliases.py` 里加表项）。用 `--rescan-rules` 追加，内置规则仍然可用：

```bash
bee fix --input semgrep.sarif --rescan-rules my_rules.py ./your-project
```

## 为什么这比「自己扩规则」划算

- Semgrep 社区规则随 CVE 更新，你不需要追
- 报告里的「可解释性 + 机器验证」是 Semgrep 不做的部分，这部分才是差异
- 检测层越弱，越该把精力放在「接住别人的结果」而不是「再造一个更差的扫描器」

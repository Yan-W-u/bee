# bee

漏洞检测 → 可解释性分析 → 补丁生成 → **机器验证**。

零第三方依赖，纯标准库，Windows / macOS / Linux 都能直接跑。

```bash
pipx install bee-scanner      # 或 pip install bee-scanner
bee --version                 # bee 1.1.0
bee scan ./your-project       # 先看有什么，纯静态、只读
```

不想装也能用：`git clone` 之后 `python -m bee scan ./your-project`。

> **关于本仓库的来源**：早期版本基于 [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi)
> （MIT）修改，未实现其声称的能力，已被完全替换。当前版本是从零重写的独立实现，
> 不含 PentAGI 的源代码。详细说明见 [NOTICE](NOTICE)。

---

## 它解决什么问题

让 LLM 改漏洞代码很容易，难的是**证明它改对了**。

市面上大多数 AI 修复工具止步于"生成一个看起来合理的 diff"。问题是 LLM 在安全修复上
有三个稳定失效模式：

1. **修表象不修根因** —— SQL 注入只加 `strip()` 或转义引号，没改成参数化。
2. **改坏别的功能** —— 顺手重构，破坏了原有行为契约。
3. **解释是套话** —— 复述 CWE 定义，说不出这段代码具体哪里错了。

bee 的应对是三层硬约束：

| 层 | 约束 |
| --- | --- |
| 解释 | 四段式 + 每条证据必须指向真实行号，行号校验不过就打回重写 |
| 补丁 | 要求精确 `old_string`/`new_string`，缩进错误自动修正，改动范围最小化 |
| 验证 | 四项机器信号全绿才算修复成立，未通过则把**具体失败原因回灌给模型重试** |

最后一条是关键。单轮生成的实际可用率很低，而验证层给出的失败信号
（"重扫仍命中" / "语法错误" / "测试失败"）几乎总能通过一次带反馈的重试修掉。

---

## 可解释性为什么是四段

少任何一段，这个修复都不可信：

| 段 | 回答的问题 | 缺失的后果 |
| --- | --- | --- |
| `root_cause` 根因 | 哪一行、哪个变量、哪个安全假设不成立 | 补丁是猜的 |
| `attack_path` 攻击路径 | 从哪个入口进、经过什么、需要什么前置条件 | 只能修表象，漏掉变体 |
| `impact` 影响面 | 具体能读到什么、执行什么、拿到什么权限 | 排不出优先级 |
| `fix_rationale` 修复原理 | 这个改动改变了什么语义边界 | 无法 review，无法说服别人 |

解释层带有反幻觉机制：`evidence` 里每条必须写成 `L行号: 结论`，工具会**强制校验**：
格式不对、行号超出文件范围、引用空行、引用函数外（import 区除外）都会打回重写。
两轮仍不合格的解释会被标记「已降级」——可以进报告（附降级标注），但**不会**再作为
补丁生成的输入，编造的根因不会把补丁带偏。

---

## 验证层的四项信号

```python
succeeded = applied and finding_gone and compiles and (tests_pass is not False)
```

| 信号 | 判定方式 |
| --- | --- |
| `applied` | 每条 `old_string` 在文件中唯一存在，替换后内容确实发生变化 |
| `finding_gone` | **重新扫描**修补后的文件，原规则不再命中 |
| `compiles` | 语法检查（`py_compile` / `node --check` / `gofmt -e`）+ 缺 import 检查 |
| `tests_pass` | 显式 `--run-tests` 开启后，在临时副本上跑 pytest / unittest / npm test / go test |

`finding_gone` 是最重要的一项。它不信任模型的自我表述，只看扫描器还报不报。
实测中「加了 trim 就说是修好了」这类补丁全靠这一项拦下来。

### 两个来自实战的补充

**基线对照。** 跑测试前先在未打补丁的副本上跑一次。项目本身就是红的（缺依赖、
缺环境变量、测试写坏）时，`tests_pass` 记为「不可用」而不是「失败」——
红基线上的非零退出码是**既有事实**，不能记成「补丁破坏了功能」。
没有这一步，一个没装 `requests` 的项目会让你看到满屏假的「补丁破坏了功能」。

**缺 import 检查。** 模型修 pickle 漏洞时会写 `io.BytesIO(...)`，修命令注入时会写
`subprocess.run(...)`，然后忘了补 `import`。`py_compile` 只检查语法不解析名字，
测试也未必覆盖到那条路径——于是 `NameError` 能一路躲过全部四项信号。
现在这类补丁会被直接拒绝并把原因回灌给模型。

**所有验证都在临时副本上进行，原仓库不会被改动。** 落盘需要显式 `--apply`，
且会为每个被改文件生成 `.bee.bak`。

---

## 多漏洞文件怎么处理

真实文件里很少只有一个漏洞。两个坑必须处理：

**累积状态。** 同一文件的第二条补丁，验证时基于「第一条已应用后」的文本，
而不是磁盘原文。否则它会在已被改掉的位置上找锚点，各自都能通过、合并时全废。

**多编辑补丁。** 修一个漏洞经常要改两处——比如改用 `subprocess.run` 就得同时
补 `import subprocess`。所以补丁协议支持一次提交多条编辑：

```json
{
  "file": "orders.py",
  "edits": [
    {"old_string": "import pickle", "new_string": "import pickle\nimport io"},
    {"old_string": "return pickle.loads(blob)", "new_string": "return _safe_load(blob)"}
  ],
  "rationale": "..."
}
```

另外，如果一条补丁顺带修掉了相邻的另一个漏洞，报告会把它标成
「已被前述补丁覆盖」而不是「修复失败」——这两件事不该混在同一个计数里。

---

## 能力一览

| 阶段 | 有什么 | 关键开关 |
| --- | --- | --- |
| 检测 | 内置 30 条规则（6 种语言 + 配置文件），可选合并 semgrep | `--detector auto\|rules\|semgrep\|both` |
| 检测 | 轻量数据流：`sql-injection` 能追「先拼变量、再 execute」 | 默认开启 |
| 检测 | 自定义规则文件 | `--rules-file my_rules.py` |
| 解释 | 四段式（根因 / 攻击路径 / 影响 / 修复原理），证据必须落到真实行号 | `audit` / `fix` 默认开启 |
| 补丁 | 一次提交多条编辑、可跨文件，缩进自动容错 | 补丁协议里的 `edits[]` |
| 补丁 | 同文件多漏洞累积应用，冲突时整条回滚不留半成品 | `fix` 默认开启 |
| 验证 | 四项信号 + 基线对照 + 缺 import 检查 + 禁止改测试文件 | `--rounds` / `--run-tests` |
| 输出 | Markdown 报告 / JSON / SARIF 2.1.0（含 `security-severity` 与 codeFlows） | `-o` / `--json` / `--sarif` |
| 增量 | 指纹不依赖行号，只报相对基线的新增问题 | `--baseline` / `--write-baseline` / `--fail-on-new` |
| 集成 | GitHub Actions（PR 检查 + 上传 SARIF）、pre-commit、GitLab / Jenkins | `.github/workflows/`、`docs/ci.md` |
| 度量 | 检测层 benchmark（16 正例 / 8 负例） | `python benchmark/run.py --strict` |

---

## 快速开始

```bash
# 只要扫描结果，不调模型
python -m bee scan ./your-project

# 扫描 + 四段式可解释性分析
python -m bee audit ./your-project -o report.md

# 扫描 + 解释 + 生成补丁 + 机器验证
BEE_LLM_API_KEY=sk-xxx python -m bee fix ./your-project -o report.md

# 验证通过后再落盘
python -m bee fix ./your-project --apply
```

不装也行，直接 `python -m bee`；装了之后 `pip install -e .` 可以用 `bee` 命令。

### 接进 CI（这是它真正该待的地方）

```bash
# 首次：把存量问题登记为基线
python -m bee scan . --write-baseline .bee-baseline.json

# 之后：只报新增问题，有新增则退出码 1
python -m bee scan . --baseline .bee-baseline.json --fail-on-new --sarif bee.sarif
```

仓库自带 `.github/workflows/bee.yml`（push/PR 都跑：单元测试 + benchmark +
增量扫描 + 上传 SARIF）、`bee-full.yml`（每周全量扫描，含 semgrep）、
`.pre-commit-hooks.yaml`（提交前拦截）、`docs/ci.md`（GitLab / Jenkins / pre-commit 写法）。

CI 门禁固定用 `--detector rules`：结果可复现，不依赖 runner 上的 docker 与镜像版本。
仓库里提交了 `.bee-baseline.json`，所以第一次跑就是「只报新增」模式；
semgrep 作为本地/周扫增强保留。

### 模型配置

兼容任何 OpenAI 协议端点（DeepSeek / OpenAI / Ollama / vLLM / OpenRouter）：

```bash
export BEE_LLM_API_KEY=sk-xxx
export BEE_LLM_BASE_URL=https://api.deepseek.com   # 默认
export BEE_LLM_MODEL=deepseek-chat                  # 默认
```

没配 key 时自动降级：规则检测照常工作，解释退化为规则先验（会明确标注），不生成补丁。

---

## 检测后端

| 模式 | 行为 |
| --- | --- |
| `--detector rules` | 只用内置 30 条规则，零依赖、离线、毫秒级 |
| `--detector semgrep` | 只用 semgrep，不可用时报错并给安装提示 |
| `--detector both` | 合并两者结果，按「文件+行号+级别」去重 |
| `--detector auto`（默认） | 探测到 semgrep 就用 both，否则退回 rules |

semgrep 在 Windows 上依赖 WSL 或 Docker，所以它是**可选增强**，不是安装门槛。
探测顺序：本地 `semgrep` 命令 → `docker` 跑 `returntocorp/semgrep` 镜像 → 回退内置规则。

为什么建议开：内置 30 条覆盖的是最高频模式化漏洞，semgrep 社区规则集有几千条。
检测覆盖面直接决定工具在真实项目里有没有用。

---

## 增量扫描与基线

成熟项目第一次扫必然几百条历史问题。每次全量报告，开发者第一天就会关掉这条流水线。

```bash
python -m bee scan . --baseline .bee-baseline.json      # 只报新增
python -m bee scan . --write-baseline .bee-baseline.json # 刷新基线
python -m bee scan . --baseline x.json --fail-on-new     # CI 用，有新增则退出码 1
```

指纹由 `路径 + 规则 + 命中行内容哈希` 组成，**不含行号**。
代码上下移动、文件里插注释都不会让已有问题变成「新增」。

基线不是垃圾桶，是「已知且已决策」的登记簿。决定暂不修的问题也刷进基线，
在 PR 里写清楚原因。

---

## SARIF 输出

```bash
python -m bee scan . --sarif bee.sarif
```

输出 SARIF 2.1.0，可直接被 GitHub Code Scanning、VS Code SARIF Viewer、
GitLab SAST 报告消费。

一个容易被忽略的细节：GitHub 用 `security-severity`（0.0–10.0）排优先级，
不是用 SARIF 的 `level`。只填 level 会让所有问题在 Security 面板里权重一样，
修复顺序就失去意义。所以这里按 CWE 区分——RCE / 全量数据泄露类给 9.8，
普通注入 8.0，信息级 3.5。

有污点路径的发现会输出 `codeFlows`，在 GitHub 上能展开看数据从哪流进来的。

---

## 常用参数

```
--min-severity {info,warning,error}   只看某个级别以上
--detector {auto,rules,semgrep,both}  选检测后端（scan / audit / fix 均生效）
--semgrep-config auto                  semgrep 规则集，可传本地目录
--rule bee.sql-injection              只跑指定规则，可重复
--include 'src/**/*.py'               只扫匹配的文件（支持 ** 跨目录）
--exclude 'tests/**'                  排除匹配的文件（支持 ** 跨目录）
--limit 10                            只处理前 N 条
--profile {strict,default,full}       规则档位：strict 只报高把握，full 含全部启发式
--input PATH.sarif                    从外部 SARIF 读 finding，跳过内置检测
--max-findings 20                     最多处理多少条（0=不限）
--max-llm-calls 120                   模型调用次数上限（估算）
--max-seconds 1800                    墙钟时间上限
--rounds 3                            每个漏洞最多重试轮次（默认 3）
--run-tests                           运行被审计仓库的测试做回归（默认关闭）
--no-tests                            强制不跑测试（兼容旧用法，等价默认值）
--no-llm                              强制离线
--baseline PATH                       只报相对基线新增的问题
--write-baseline PATH                 把当前结果写成基线
--fail-on-new                         有新增问题时退出码 1
--fail-on-findings                    还有发现就退出码 1（CI 门禁）
--sarif PATH                          输出 SARIF 2.1.0
--json                                结构化输出
--apply --yes                         落盘（先备份）
```

---

## 安全边界：在跑不可信仓库之前

`bee fix` 会在临时副本里执行**被审计仓库自己的测试代码**（在 `--run-tests` 开启时），
这等于执行任意代码。已经做的防护：

- 回归测试**默认关闭**，显式 `--run-tests` 才开，交互终端还会再确认一次；
- 测试子进程的环境变量按名单剥离（`BEE_LLM_*` / `*_KEY` / `*_TOKEN` / 云凭据），
  API Key 不会随测试代码泄露；
- 补丁路径经 `safe_join` 校验，`../`、绝对路径、符号链接一律拒绝写入；
- 落盘拦截测试文件、CI 配置、构建配置、`.env*`、密钥文件、`.git/`（大小写不敏感）。

仍然要遵守的一条：**只对可信仓库运行 fix**，或者放进容器/虚拟机再跑。
临时副本不是沙箱，它防的是改文件，防不了执行代码。`scan` 是纯静态的，
可以放心跑任何仓库。

另外两条：

- `--rules-file` 会 **exec 该 Python 文件**（与 `python your_rules.py` 等价），
  只加载自己写的规则文件。
- semgrep 的 docker 模式把仓库以**只读**方式挂进容器，镜像固定版本
  （`returntocorp/semgrep:1.182.0`，可用环境变量 `BEE_SEMGREP_IMAGE` 覆盖）。
  docker 模式等于信任该镜像。

---

## 内置规则

30 条，覆盖 Python / JavaScript / TypeScript / Go / Java / PHP，外加 YAML / JSON / .env 配置。

| 规则 | CWE | 级别 |
| --- | --- | --- |
| `sql-injection` | CWE-89 | 高危 |
| `command-injection` | CWE-78 | 高危 |
| `code-injection` | CWE-94/95 | 高危 |
| `ssti` | CWE-1336 | 高危 |
| `nosql-injection` | CWE-943 | 高危 |
| `ldap-injection` | CWE-90 | 高危 |
| `dynamic-order-by` | CWE-89 | 高危 |
| `path-traversal` | CWE-22 | 高危 |
| `zip-slip` | CWE-22 | 高危 |
| `unsafe-deserialization` | CWE-502 | 高危 |
| `xxe` | CWE-611 | 高危 |
| `prototype-pollution` | CWE-1321 | 高危 |
| `private-key-hardcoded` | CWE-321 | 高危 |
| `cloud-credential` | CWE-798 | 高危 |
| `jwt-verify-disabled` | CWE-347 | 高危 |
| `hardcoded-credential` | CWE-798 | 中危 |
| `ssrf` | CWE-918 | 中危 |
| `xss` | CWE-79 | 中危 |
| `open-redirect` | CWE-601 | 中危 |
| `csrf-disabled` | CWE-352 | 中危 |
| `cors-wildcard` | CWE-942 | 中危 |
| `unrestricted-upload` | CWE-434 | 中危 |
| `weak-crypto` | CWE-327 | 中危 |
| `insecure-random` | CWE-330 | 中危 |
| `tls-verify-disabled` | CWE-295 | 中危 |
| `sensitive-data-logging` | CWE-532 | 中危 |
| `insecure-cookie` | CWE-614 | 中危 |
| `redos` | CWE-1333 | 中危 |
| `timing-attack` | CWE-208 | 提示 |
| `debug-enabled` | CWE-489 | 提示 |

除了单条正则，`sql-injection` 还有一条轻量数据流通道（`_detect_sql_flow`）：
追踪「先拼成变量、再交给 execute」的写法。纯正则跨不过语句边界，
而这恰恰是真实代码最常见的形态。

### 自定义规则

写一个 Python 文件，定义 `RULES` 列表：

```python
from bee.detect import Rule
from bee.models import Severity

RULES = [
    Rule(
        id="myorg.internal-api-key",
        title="内部 API Key 泄露",
        severity=Severity.ERROR,
        cwe=["CWE-798"],
        owasp=["A07:2021"],
        languages=["python", "go"],
        pattern=r"internal_key\s*=\s*['\"][a-f0-9]{32}['\"]",
        # 命中这些则认为是安全写法，压制误报
        safe_when=[r"os\.getenv"],
        # 规则自带的先验，会作为可解释性分析的输入
        root_cause_hint="内部 API Key 硬编码在源码里",
        fix_hint="改为从配置中心或环境变量注入",
    ),
]
```

```bash
python -m bee audit ./src --rules-file my_rules.py
```

> ⚠️ `--rules-file` 会 **执行该 Python 文件的代码**（import 语义，等价
> `python my_rules.py`）。只加载自己写的规则文件，不要加载第三方仓库里
> 未审阅的规则文件。

---

## 检测层 benchmark

```bash
python benchmark/run.py              # 人类可读表格
python benchmark/run.py --strict     # 出现 FN / FP 时退出码 1，可进 CI
```

只衡量**规则引擎**，不调 LLM——补丁质量依赖模型版本和温度，不可复现；
检测层的准确率是确定的，可以进 CI 看趋势。

样本在 `benchmark/cases/`，正例 16 个（Py / JS / Go / PHP / YAML，含多跳拼接、
`eval(变量)`、Go 的 `md5.Sum`、PHP 的 `.` 拼接、配置文件冒号凭据、lxml 默认 XXE），
负例 8 个（参数化查询、f-string 只拼白名单表名、列表形式 `subprocess`、
`textContent`、白名单 order-by、`resolve_entities=False` 等常见误报陷阱）。
行号允许 ±1 偏差。

```
正例 16 / 负例 8   →   TP 16  FN 0  FP 0
Precision 100.0%   Recall 100.0%   F1 100.0%
```

这个数字不要当准确率对外引用（见下方已知限制第 9 条），它的用途是回归：
改规则时如果 FN 或 FP 变了，CI 会立刻告诉你。

### 真实语料上的噪音

构造样本证明不了真实项目里的表现。`benchmark/realworld.py` 换成真实代码：

```bash
python benchmark/realworld.py --check          # 超阈值退出码 1
python benchmark/realworld.py --sample 12      # 生成人工标注表
```

| 语料 | 发现数（v1.0.0 → v1.1.0） | 说明 |
| --- | --- | --- |
| CPython stdlib（536 文件） | 321 → **77** | 词边界、按语言拆分、字符串过滤、凭据启发式 |
| 本机 site-packages | — → **18** | 第三方包的 tls / code-injection 命中 |
| bee 自身 | 0 → **0** | 自扫必须保持干净 |

剩下的 77 条大多是**真实的危险 API 调用**（`eval` 在调试器里、`marshal.loads`
在 importlib 里）——规则只看单行，分不清「实现这个功能」和「误用这个功能」。
这就是为什么报告必须人 review。详细拆解见 [docs/validation.md](docs/validation.md)。

---

## 已知限制

这些是实际边界，不要指望它做到：

1. **检测上限由规则决定。** 内置 30 条规则覆盖的是最常见的模式化漏洞，
   业务逻辑漏洞（越权、竞争条件、状态机绕过）它发现不了。它是 LLM 辅助的
   规则扫描器，不是 CodeQL。开 `--detector semgrep` 能补上几千条社区规则，
   但仍然换不来跨过程的数据流分析。
2. **`finding_gone` 证明的是「该规则不再命中」，不等于「逻辑上安全」。**
   绕过规则的写法同样能骗过这一项。所以仍然需要人 review 补丁。
3. **缺 import 检查只覆盖标准库名单。** 第三方库的同名情况不判，
   宁可漏报也不误报——误报会白白浪费一轮重试。
4. **补丁可以跨文件，但不会替你找调用点。** 一次提交里的多条编辑可以落在
   不同文件上（改 `utils.py` 的拼接函数 + 改 `orders.py` 的调用都行）。
   但「另一个文件里还有一处同样的写法」这种搜索工具不做——它只在
   `side_effects` 里写明还需要改哪里。跨文件补丁的验证同样走四项信号，
   只是 `tests_pass` 的覆盖面取决于项目自己的测试。
5. **`tests_pass` 默认不跑**（`--run-tests` 显式开启），且依赖项目本身有测试。
   没有测试或测试跑不起来的项目，只能验证到语法层，这件事工具会在报告里
   明确写出来，不会假装通过。项目原有测试就是红的，记「不可用」不记「失败」。
6. **规则文本会被自己命中。** 已经加了注释行和正则文本的过滤，但含大量安全
   模式定义的项目仍可能产生少量误报，用 `--exclude` 排除规则目录。
7. **不替代专业 SAST。** 如果是合规要求（等保、PCI-DSS），该上 Semgrep / CodeQL /
   Fortify。这个工具的价值在「发现之后怎么修」，不是在发现阶段做到多全。
8. **semgrep 后端在 Windows 上依赖 WSL 或 Docker。** 两者都不可用时自动退回内置
   规则，不会报错阻断。也就是说 Windows 上的默认体验就是 `--detector rules`。
9. **benchmark 的数字偏乐观。** `benchmark/cases` 里的样本是照着规则能力写的，
   16/16 命中只证明「规则按设计工作」，不代表真实项目的检出率。它适合进 CI
   看回归趋势，不适合当准确率指标对外引用。
10. **stdlib 上的 77 条里仍有误报，别把「噪音下降」当成「准确」。** 标准库是
    `eval`/`pickle` 这些危险 API 的实现方，天然会被打中。要测真实 FP 率需要
    **应用代码 + 人工标注**的语料，目前还没有——这是 v1.1.0 明确缺口。规则层
    建议用 `--profile strict` 进门禁，`default` 给人看。
11. **`--input` 导入的 finding 无法验证「漏洞消失」。** 外部规则不在 bee 内，
    重扫会得到假的「已修复」，所以 `finding_gone` 记为 `None`，这类补丁永远不会
    显示「已验证」。要完整验证就补一条等价的自定义规则（见
    [docs/semgrep-integration.md](docs/semgrep-integration.md)）。
12. **大仓库的成本有上限但没有硬预算。** 调用方搜索最多扫 2000 个文件、单条
    finding 的上下文有字符预算，但每条补丁仍要复制一次完整项目、`--run-tests`
    时还要跑一遍全量测试。几十万行的仓库建议先 `--limit` / `--min-severity`。

### 实测数据

在内置样本（9 个漏洞，单一文件）上跑 DeepSeek：

```
9 条发现 → 8 条补丁通过机器验证 + 1 条被前述补丁覆盖 + 0 条失败
重扫结果：0 发现
原有 5 个回归测试：全部通过
```

不同轮次会有波动（LLM 每次生成的补丁不一样），4 轮上限下偶有 1 条失败，
报告会如实标成「未通过验证」而不是硬凑一个结果。

完整报告见 [`examples/report_example.md`](examples/report_example.md)
（9 条发现的四段式解释 + 每条补丁的验证信号明细）。

---

## 设计上的取舍

**为什么 semgrep 是可选而不是默认？** 它在 Windows 上依赖 WSL 或 Docker，
两者在不少环境里都不可靠。如果把它设成硬依赖，工具在这些机器上直接不可用。
所以内置规则引擎保底——零依赖、离线可用、每条规则自带可解释性先验；
探测到 semgrep 就合并它的结果。代价是默认体验下规则生态只有 30 条，
这是明确的权衡，不是疏忽。

**为什么用 `old_string`/`new_string` 而不是裸 diff？** LLM 生成的 unified diff
在行号偏移、上下文行上出错率很高。精确字符串替换 + 唯一性校验 + 缩进容错，
落地成功率明显更高，而且天然避免了"改错地方"。

**为什么验证层要复制整个项目？** 跑测试需要完整上下文。
代价是大项目会慢。默认不开回归测试（`--run-tests` 才开），只做语法检查就够快；
调用方搜索有文件数上限，单条 finding 的上下文也有字符预算，防止在大仓库上失控。

---

## 测试

```bash
python -m unittest discover -s tests -v
python benchmark/run.py --strict      # 检测层准确率回归
```

138 个用例覆盖十一块：

- `tests/test_verify.py` —— 四项信号是否真的在拦截（含"能应用能编译但没修好"、
  "语法被改坏"、沙箱隔离三个关键用例）
- `tests/test_repair_loop.py` —— 失败回灌是否真的把原因和 diff 传回模型、
  缩进容错是否生效、无 key 时是否正确降级
- `tests/test_session.py` —— 同文件多漏洞的累积修复、跨文件编辑、冲突时不留半成品、
  每文件只备份一次
- `tests/test_imports.py` —— 缺 import 检测（含局部变量遮蔽、非标准库不误报）
- `tests/test_guard.py` —— 模型改测试文件 / 改受保护路径时是否被硬拦截
- `tests/test_sarif_baseline.py` —— SARIF 结构与 `security-severity`、
  指纹稳定性（插注释、移动行号不产生假「新增」）、tags 去重
- `tests/test_semgrep.py` —— semgrep 输出转换、CWE/OWASP 去重、不可用时静默回退
- `tests/test_detect.py` —— 单条规则的判定边界，重点是 `safe_when` 压制是否生效
  （参数化 SQL、`shell=False`、`resolve_entities=False`、YAML 环境变量注入、
  f-string 白名单表名 vs `request.args` 用户输入）
- `tests/test_inputs.py` —— 外部 SARIF 导入（字段映射、去重、未重扫状态）
- `tests/test_audit_fixes.py` —— 外部审计的验收场景：红基线不误判、自定义规则
  finding_gone 不恒真、`--exclude` 的 `**` 语义、编造证据被打回、路径穿越与
  符号链接被拒绝、测试子进程环境变量剥离、`scan -o` 与 `--fail-on-findings`

跑法不依赖 pytest。

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/scope.md](docs/scope.md) | **适用范围与边界**：它不是什么、能不能当门禁、`finding_gone` 证明什么 |
| [docs/validation.md](docs/validation.md) | 检测层真实数据：stdlib 321→77 的拆解、剩余命中的性质 |
| [docs/semgrep-integration.md](docs/semgrep-integration.md) | 把 Semgrep / CodeQL 的结果接进来，bee 只做修复层 |
| [docs/ci.md](docs/ci.md) | GitHub Actions / GitLab / Jenkins / pre-commit 接入 |
| [docs/docker.md](docs/docker.md) | 在容器里跑 `fix`（隔离目标仓库的代码执行） |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 开发环境、写规则的步骤、PR 要求 |
| [SECURITY.md](SECURITY.md) | 漏洞报告流程、安全边界 |

## 来源与许可

**本仓库当前版本（v1.0 起）为独立实现，MIT 协议，版权归 Yan-W-u。**

早期版本（2026-06 至 2026-09）是 [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi)
的修改版本，保留其 Go 后端与 React 前端。那一版没有实现漏洞检测与修复的后端逻辑，
只有前端占位页面，因此已被完全替换，不再包含任何 PentAGI 代码。

产品的方向——自动化安全检测、可解释性修复、把检测与修复串成可验证流水线——
受到 PentAGI 的启发。这一层致谢写进了 [NOTICE](NOTICE)，其中也附了 PentAGI 的
完整 MIT 许可声明（Copyright (c) 2025 PentAGI Development Team），
供需要查阅早期版本代码的人参考。

当前版本不包含、不链接、不间接调用 PentAGI 及其组件
（`vxcontrol/cloud`、`vxcontrol/langchaingo`、`vxcontrol/graphiti-go-client`），
运行时零依赖。

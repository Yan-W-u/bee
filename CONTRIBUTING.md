# 参与开发

## 环境

```bash
git clone https://github.com/Yan-W-u/bee.git
cd bee
python -m pip install -e .
python -m bee --version
```

零运行时依赖，不用建虚拟环境也能跑。开发只需要 Python ≥ 3.10。

## 三条必跑命令

改任何东西之前先记住这三条，提交前必须全绿：

```bash
python -m unittest discover -s tests -v   # 138 个用例
python benchmark/run.py --strict          # 规则层 16 正例 / 8 负例，0 FP 0 FN
python benchmark/realworld.py --check     # 真实语料噪音阈值
```

第三条衡量的是「误报有没有回涨」。改规则时最危险的失败模式是
**为了消一个误报，把真漏洞也一起消掉了**——所以 `--strict` 和 realworld
要一起看。

## 写一条新规则

1. 在 `bee/detect.py` 的 `BUILTIN_RULES` 里加 `Rule(...)`，必须填 `cwe`、
   `languages`、`root_cause_hint`、`fix_hint`（后两个是解释层的输入，不能省）。
2. 在 `_CONFIDENCE_BY_ID` 里登记把握度（HIGH/MEDIUM/LOW）。
   不登记会有测试失败——这是刻意的，避免新规则悄悄混进默认档。
3. 如果命中天然落在字符串里（PEM 私钥、云密钥），设 `allow_in_strings=True`。
4. 如果不同语言的危险写法不同，用 `pattern_by_lang` 而不是把差异塞进一个正则。
5. 在 `benchmark/cases/` 加正例，在 `manifest.json` 登记；能构造出负例就一起加。
6. 在 `tests/test_detect.py` 加边界用例，至少包含「不该报的那个写法」。

规则宁窄勿宽。一条误报的成本不是「多看一眼」，是使用者关掉整条流水线。

## 改验证层

`bee/verify.py` 是全项目最不能出错的地方。它决定「补丁是否算修好了」，
任何放宽都必须有对应的负例测试：能让坏补丁通过验证的改动，一律不接受。

四条信号的含义不要动：

- `applied`：`old_string` 唯一匹配且内容真的变了
- `finding_gone`：用同一规则集重扫，不再命中
- `compiles`：语法检查 + 缺 import 检查
- `tests_pass`：只在 `--run-tests` 时跑；红基线记 `None` 不记 `False`

## PR 要求

- 一个 PR 一件事，不要混「规则改动」和「重构」
- 三条命令的输出贴到 PR 描述里（数字有变化要解释）
- 改了行为就同步改 `README.md` / `docs/`，文档落后期望会被 review 打回
- 不要提交 `.bee.bak`、临时 SARIF、个人 API key

## 报告问题

- 漏洞：见 [SECURITY.md](../SECURITY.md)，不要开公开 issue
- 规则误报：开 issue 附**能复现的最小代码片段**（3–5 行），不要只贴截图
- 规则漏报：同上，附你认为应该命中的那一行和期望的规则名

## 代码风格

- 注释解释**为什么**，不复述代码在做什么
- 中文注释可以，变量名/函数名用英文
- 不引入第三方依赖。这条是硬约束：`pip install bee-scanner` 之后什么都不用装

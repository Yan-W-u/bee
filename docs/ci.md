# 接入 CI

三条命令就能把它塞进现有流水线，不需要跑服务、不需要数据库。

```bash
# 1. 首次：把当前存量问题写成基线
python -m bee scan . --write-baseline .bee-baseline.json

# 2. 之后：只报相对基线新增的问题，有新增则退出码 1
python -m bee scan . --baseline .bee-baseline.json --fail-on-new

# 3. 需要给 GitHub / IDE 看的时候再输出 SARIF
python -m bee scan . --baseline .bee-baseline.json --sarif bee.sarif
```

基线的意义：成熟项目第一次扫必然几百条历史问题。每次都全量报告，
开发者第一天就会把这个流水线关掉。基线让工具只对**新引入**的问题负责。

---

## GitHub Actions

仓库自带两个 workflow，复制即可：

| 文件 | 触发时机 | 做什么 |
| --- | --- | --- |
| `.github/workflows/bee.yml` | PR / push main | 只报新增问题，上传 SARIF 到 Code Scanning |
| `.github/workflows/bee-full.yml` | 每周一 + 手动 | 全量扫描，含已进入基线的历史问题 |

第一次跑时如果没有 `.bee-baseline.json`，workflow 会自动生成并提示你把它提交进仓库。
**记得提交**，否则每次都当成首次运行。

想启用可解释性分析与补丁生成，在仓库 Secrets 里加 `BEE_LLM_API_KEY`。
不配也能用——规则检测不需要任何外部依赖。

SARIF 上传需要 `security-events: write` 权限，workflow 里已经声明。

---

## GitLab CI

```yaml
bee-scan:
  image: python:3.12-slim
  script:
    - python -m bee scan . --baseline .bee-baseline.json --fail-on-new --sarif bee.sarif
  artifacts:
    when: always
    paths: [bee.sarif]
    reports:
      sast: bee.sarif
```

GitLab 的 `reports:sast` 接受 SARIF，会直接展示在 Merge Request 的 Security 面板里。

---

## pre-commit

`.pre-commit-hooks.yaml` 已经写好，用户侧加三行：

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yan-W-u/bee
    rev: main
    hooks:
      - id: bee
```

只跑规则引擎，30 条规则扫中小项目通常在 1 秒内，不拖慢提交。

想连 LLM 分析一起跑（会慢几十秒），把 args 里的 `--min-severity error` 换成自己的偏好，
并设置 `BEE_LLM_API_KEY` 环境变量。

---

## Jenkins / 任意 shell 环境

```groovy
stage('Security') {
    steps {
        sh 'python -m bee scan . --baseline .bee-baseline.json --fail-on-new --sarif bee.sarif'
    }
    post {
        always {
            archiveArtifacts artifacts: 'bee.sarif', allowEmptyArchive: true
        }
    }
}
```

退出码约定：`0` 无新增，`1` 有新增（被 `--fail-on-new` 触发），`2` 路径错误。

---

## 怎么更新基线

修完一批问题后，把基线刷新一次，否则已修掉的问题仍会占用基线额度（虽然不影响判断，
但会让基线文件越来越脏）：

```bash
python -m bee scan . --write-baseline .bee-baseline.json
git add .bee-baseline.json && git commit -m "chore: 刷新 bee 基线"
```

新增问题如果经评估决定暂不修（比如第三方代码里的），也直接刷进基线，
并在 PR 描述里写清楚为什么不修。**基线不是垃圾桶，是「已知且已决策」的登记簿。**

---

## 为什么建议同时开 semgrep

内置 30 条规则覆盖的是最高频的模式化漏洞。真实项目里规则覆盖面直接决定它有没有用。
如果 CI 环境能跑 Docker，加一个 `--detector both` 就能把 semgrep 的社区规则集并进来：

```yaml
- name: 扫描（bee + semgrep）
  run: docker info && python -m bee scan . --detector both --baseline .bee-baseline.json
```

结果会按「文件 + 行号 + 严重级别」去重合并，同一处问题不会出现两遍。
semgrep 不可用时自动回退到内置规则，不会让流水线红掉。

---

## 顺手跑一次自检

bee 自己也有回归保护。改了规则或者补丁验证逻辑之后，在 CI 里加一步：

```yaml
- name: 单元测试
  run: python -m unittest discover -s tests
- name: 规则 benchmark（出现漏报或误报则失败）
  run: python benchmark/run.py --strict
```

`--strict` 在出现 FN 或 FP 时退出码 1。它衡量的是规则引擎，不调 LLM，
所以结果是确定的、可复现的——适合当趋势看，不适合当准确率对外引用。

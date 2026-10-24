# 在容器里跑 fix

`bee fix` 会执行目标仓库的测试代码（`--run-tests`）并读写项目文件。
对不完全信任的仓库，放进容器是对的做法——容器不是万能沙箱，
但比在宿主机直接跑安全得多。

## 构建

```bash
docker build -t bee .
```

镜像以非 root（uid 10001）运行，`WORKDIR` 是 `/src`。

## 扫描（只读，最安全）

```bash
docker run --rm -v "$PWD:/src:ro" bee scan /src --detector rules
```

`-v ...:ro` 是必须的：扫描本来就不该写目标目录。

## 生成并验证补丁（不落盘）

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e BEE_LLM_API_KEY \
  bee fix /src --limit 5 --no-tests
```

补丁在容器内的临时副本上验证，报告写到 stdout；不传 `--apply` 就不会动宿主文件。

## 落盘（确认 diff 之后）

```bash
docker run --rm -v "$PWD:/src" -e BEE_LLM_API_KEY bee fix /src --apply --yes --limit 1
```

每个被改文件会先生成 `.bee.bak`。落盘前务必看过报告里的 diff。

## 注意事项

- **不要**挂载 `~/.ssh`、`~/.aws`、`.env`——那等于把凭据交给被审计仓库的测试代码
- `--run-tests` 在容器里相对安全，但恶意代码仍可读写挂载目录、发起网络请求
- 需要严格隔离时加 `--network none`（此时只能 `--no-llm`，无法调用模型）
- 容器内没有 git，`fix` 只改文件；提交请回宿主机做

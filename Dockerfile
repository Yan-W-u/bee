# bee 的容器镜像：把 fix 的代码执行关进容器
FROM python:3.12-slim

LABEL org.opencontainers.image.title="bee" \
      org.opencontainers.image.description="漏洞检测 + 可解释性修复 + 机器验证" \
      org.opencontainers.image.source="https://github.com/Yan-W-u/bee" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY bee ./bee
RUN pip install --no-cache-dir .

# 以非 root 运行：被审计仓库的测试代码也拿不到 root
RUN useradd --create-home --uid 10001 bee
USER bee
WORKDIR /src

ENTRYPOINT ["bee"]
CMD ["--help"]

# mcpguard 明棱 - MCP Server 模式镜像
# Glama 部署用：启动 MCP server 响应 introspection 检查
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY mcpguard/ ./mcpguard/
# 安装含 MCP 适配层（mcp extras 不破坏默认零依赖属性）
RUN pip install --no-cache-dir ".[mcp]"

# 默认 stdio 模式（Glama 检查用）
ENTRYPOINT ["python", "-m", "mcpguard.server_mcp"]
CMD []

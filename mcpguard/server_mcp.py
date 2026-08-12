"""明棱 MCPGuard 的 MCP Server 模式。

把扫描功能暴露成 MCP 工具，让 AI Agent 可以直接调用：
- scan：扫描本机默认位置（MCP 配置 + skill 目录）
- scan_path：扫描指定路径

这样 mcpguard 既是零依赖 CLI，又是可被 Agent 调用的 MCP server。

用法：
    python -m mcpguard.server_mcp          # stdio 模式（默认）
    python -m mcpguard.server_mcp --http   # streamable HTTP 模式

依赖：需要安装 mcp 库（pip install mcp 或 pip install "mcpguard[mcp]"）。
"""

from __future__ import annotations

import argparse
import json
import sys

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("[错误] 未安装 mcp 库。请运行: pip install mcp 或 pip install \"mcpguard[mcp]\"", file=sys.stderr)
    sys.exit(1)

from . import __version__
from .report import ReportBuilder
from .rules import build_default_engine
from .scanner import Scanner


def _result(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False)


mcp = FastMCP(
    "mcpguard",
    instructions="明棱 MCPGuard：扫描 MCP server 配置和 skill 目录，检测工具描述中的投毒特征（提示注入、同形字、Unicode 隐形字符、危险 shell、静默外发等）。",
)


def _do_scan(paths):
    """执行扫描，返回结果 dict。"""
    engine = build_default_engine()
    scanner = Scanner(extra_paths=paths)
    targets = scanner.scan_all()
    results = ReportBuilder(engine).build(targets)
    return {
        "ok": True,
        "targets": len(results),
        "report": json.loads(ReportBuilder.to_json(results)),
    }


@mcp.tool()
def scan(default_paths: bool = True) -> str:
    """扫描本机默认位置（常见 MCP 配置 + skill 目录），返回安全报告。"""
    return _result(_do_scan(None))


@mcp.tool()
def scan_path(path: str) -> str:
    """扫描指定目录或文件，返回安全报告。"""
    return _result(_do_scan([path]))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mcpguard-server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    if args.transport == "http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())

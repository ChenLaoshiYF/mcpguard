"""鉴盾 (MCPGuard) 命令行入口。

用法:
    python -m mcpguard                      # 扫描本机默认位置
    python -m mcpguard --path <目录/文件>   # 扫描指定路径
    python -m mcpguard --json               # 输出 JSON 报告
    python -m mcpguard --version            # 版本
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .report import ReportBuilder
from .rules import build_default_engine
from .scanner import Scanner


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpguard",
        description="鉴盾 MCPGuard — 本地 AI Agent 安全扫描器",
    )
    parser.add_argument("--path", action="append", default=None,
                        help="额外扫描的目录或文件（可多次指定）")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 格式输出报告")
    parser.add_argument("--version", action="version",
                        version=f"mcpguard {__version__}")
    args = parser.parse_args(argv)

    # 构建引擎与扫描器
    engine = build_default_engine()
    scanner = Scanner(extra_paths=args.path)
    targets = scanner.scan_all()

    # 执行检测
    builder = ReportBuilder(engine)
    results = builder.build(targets)

    # 输出
    if args.json:
        print(builder.to_json(results))
    else:
        print(builder.to_text(results))

    return 0


if __name__ == "__main__":
    sys.exit(main())

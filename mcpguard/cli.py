"""鉴盾 (MCPGuard) 命令行入口。

用法:
    python -m mcpguard                      # 扫描本机默认位置
    python -m mcpguard --path <目录/文件>   # 扫描指定路径
    python -m mcpguard --json               # 输出 JSON 报告
    python -m mcpguard --version            # 版本

退出码:
    0  扫描完成且无 critical/high 命中
    1  扫描完成但存在 critical/high 命中（CI 可据此判断）
    2  执行出错（参数错误、IO 异常等）
"""

from __future__ import annotations

import argparse
import sys

# Windows 控制台默认 GBK，无法输出部分 Unicode；强制 UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from . import __version__
from .report import ReportBuilder
from .rules import build_default_engine
from .scanner import Scanner


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 9)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpguard",
        description="鉴盾 MCPGuard — 本地 AI Agent 安全扫描器",
    )
    parser.add_argument("--path", action="append", default=None,
                        help="额外扫描的目录或文件（可多次指定）")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 格式输出报告")
    parser.add_argument("--exit-code", action="store_true",
                        help="存在 critical/high 时退出码返回 1（供 CI 使用）")
    parser.add_argument("--version", action="version",
                        version=f"mcpguard {__version__}")
    args = parser.parse_args(argv)

    try:
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

        # 退出码：--exit-code 且存在 critical/high 时返回 1
        if args.exit_code:
            for r in results:
                for f in r.findings:
                    if _severity_rank(f.severity) <= 1:  # critical / high
                        return 1
        return 0

    except KeyboardInterrupt:
        print("\n[中断] 用户取消扫描", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[错误] 扫描失败: {e}", file=sys.stderr)
        print("如果这是意外错误，请到项目仓库提交 issue。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

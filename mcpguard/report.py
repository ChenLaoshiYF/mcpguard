"""报告生成：汇总扫描结果，输出人类可读的安全报告。

两种输出：
- 终端文本（默认）
- JSON（--json，供程序消费）
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List

from .rules import Finding, RuleEngine, severity_score

# 报告脱敏：识别长密钥形态（ghp_/sk-/github_pat_/Bearer 等），打印前打码
_SECRET_PATTERNS = [
    re.compile(r"(ghp_|github_pat_|sk-|sk_|xoxb-|AIza|AKIA)[A-Za-z0-9_\-]{10,}"),
    re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{10,}", re.I),
    re.compile(r"(token\s*[=:]\s*)[A-Za-z0-9._\-]{8,}", re.I),
    re.compile(r"(password\s*[=:]\s*)[^\s,;\"]{6,}", re.I),
]


def _redact(text: str) -> str:
    """把文本中的密钥形态替换为 ***，防止报告泄露凭据。"""
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(1) + "***" if m.lastindex else "***", text)
    return text


@dataclass
class TargetResult:
    """一个目标的扫描结果。"""

    target_name: str
    kind: str
    path: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return severity_score(self.findings)

    @property
    def max_severity(self) -> str:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
        worst = ""
        for f in self.findings:
            if order.get(f.severity, 9) < order.get(worst, 9):
                worst = f.severity
        return worst or "clean"


class ReportBuilder:
    """把扫描结果组织成报告。"""

    def __init__(self, engine: RuleEngine):
        self.engine = engine

    def build(self, targets) -> List[TargetResult]:
        """对每个目标跑规则引擎，返回结果列表。"""
        results = []
        for t in targets:
            findings = self.engine.scan(t.content, source=f"{t.name} ({t.path})")
            results.append(
                TargetResult(
                    target_name=t.name,
                    kind=t.kind,
                    path=t.path,
                    findings=findings,
                )
            )
        return results

    # ------------------------------------------------------------------
    # 文本输出
    # ------------------------------------------------------------------
    @staticmethod
    def to_text(results: List[TargetResult]) -> str:
        lines = []
        lines.append("=" * 62)
        lines.append("  鉴盾 MCPGuard — AI Agent 安全扫描报告")
        lines.append("=" * 62)

        total_findings = sum(len(r.findings) for r in results)
        if not results:
            lines.append("\n未发现可扫描的目标（本机可能没有 MCP 配置或 skill 目录）。")
            lines.append("可用 --path 指定要扫描的目录或文件。")
            return "\n".join(lines)

        lines.append(f"\n扫描目标: {len(results)} 个 | 命中: {total_findings} 条\n")

        for r in results:
            mark = "[PASS]" if r.score == 100 else ("[WARN]" if r.score >= 70 else "[FAIL]")
            lines.append(f"{mark} [{r.score:3d}/100] {r.target_name}")
            lines.append(f"    类型: {r.kind} | 路径: {r.path}")
            if r.findings:
                for f in r.findings:
                    sev = f.severity.upper()
                    lines.append(f"    [x] [{sev}] {f.title} ({f.rule_id})")
                    lines.append(f"        [x] 命中: {_redact(f.excerpt)}")
            lines.append("")

        # 汇总
        lines.append("-" * 62)
        lines.append("汇总:")
        crit = sum(1 for r in results for f in r.findings if f.severity == "critical")
        high = sum(1 for r in results for f in r.findings if f.severity == "high")
        med = sum(1 for r in results for f in r.findings if f.severity == "medium")
        lines.append(f"  critical: {crit} | high: {high} | medium: {med} | 其余: {total_findings - crit - high - med}")
        if crit:
            lines.append("\n[!] 发现 critical 级风险：工具描述可能存在投毒指令，")
            lines.append("  建议立即停止使用对应 MCP server，并人工检查其来源。")
        lines.append("\n说明: 规则检测仅提示可疑特征，不构成最终判定；")
        lines.append("      高风险项请结合人工审查确认。")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON 输出
    # ------------------------------------------------------------------
    @staticmethod
    def to_json(results: List[TargetResult]) -> str:
        payload = {
            "scan_time": __import__("datetime").datetime.now().isoformat(),
            "summary": {
                "targets": len(results),
                "findings": sum(len(r.findings) for r in results),
            },
            "targets": [
                {
                    "name": r.target_name,
                    "kind": r.kind,
                    "path": _redact(r.path),
                    "score": r.score,
                    "max_severity": r.max_severity,
                    "findings": [
                        {
                            "rule_id": f.rule_id,
                            "severity": f.severity,
                            "title": f.title,
                            "excerpt": _redact(f.excerpt),
                            "source": f.source,
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

"""报告生成：汇总扫描结果，输出人类可读的安全报告。

两种输出：
- 终端文本（默认）
- JSON（--json，供程序消费）
"""

from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List

from .rules import Finding, RuleEngine, severity_score

# 报告脱敏：识别各类凭据形态，打印前打码（保留前缀便于识别类型）
_SECRET_PATTERNS = [
    # 平台 token（ghp_/sk-/github_pat_/glpat-/sk-ant- 等）
    re.compile(r"(ghp_|gho_|ghu_|ghr_|github_pat_|glpat-|sk-ant-|sk-|sk_|xoxb-|AIza|AKIA)[A-Za-z0-9_\-]{10,}"),
    # Bearer / Basic 认证
    re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{10,}", re.I),
    re.compile(r"(Basic\s+)[A-Za-z0-9+/=]{10,}", re.I),
    # token= / token: / api_key= 等赋值形态（含引号包裹）
    re.compile(r"((?:token|api[_-]?key|secret|access[_-]?key|client[_-]?secret)\s*[=:]\s*[\"']?)[^\s,;\"']{8,}", re.I),
    # password= / password: （含引号包裹）
    re.compile(r"(password\s*[=:]\s*[\"']?)[^\s,;\"']{6,}", re.I),
    # JWT（三段 base64url）
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # URL 内嵌凭据 https://user:pass@host
    re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@", re.I),
]

# SSH 私钥块
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.S,
)


def _redact(text: str) -> str:
    """把文本中的凭据形态替换为 ***，防止报告泄露。"""
    # 先处理多行私钥块
    text = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    for pat in _SECRET_PATTERNS:
        # 有捕获组（group 1）时保留前缀，无捕获组（JWT/URL）时整个替换
        if pat.groups:
            text = pat.sub(lambda m: m.group(1) + "***", text)
        else:
            text = pat.sub("***", text)
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
            lines.append(f"    类型: {r.kind} | 路径: {_redact(r.path)}")
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
        low = sum(1 for r in results for f in r.findings if f.severity == "low")
        info = sum(1 for r in results for f in r.findings if f.severity == "info")
        lines.append(f"  critical: {crit} | high: {high} | medium: {med} | low: {low} | info: {info}")
        if crit:
            lines.append("")
            lines.append("[!] 存在 critical 级命中：工具描述可能包含投毒指令，")
            lines.append("    也可能只是文档中引用了攻击案例。请人工核对后判断。")
        lines.append("")
        lines.append("评分说明: 评分 = 100 - 扣分(critical:-40, high:-20, medium:-8, low:-3, info:-1)。")
        lines.append("  90+ 低风险 | 70-89 建议核查 | 50-69 中风险 | <50 需重点关注。")
        lines.append("  注意: 评分反映规则命中情况，不代表实际攻击。请逐条人工核对。")
        lines.append("")
        lines.append("免责声明: 检测基于关键词规则，可能产生误报；")
        lines.append("          规则无法检测语义变体的注入，请勿仅凭报告做安全结论。")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON 输出
    # ------------------------------------------------------------------
    @staticmethod
    def to_json(results: List[TargetResult]) -> str:
        payload = {
            "scan_time": datetime.datetime.now().isoformat(),
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
                            "source": _redact(f.source),
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

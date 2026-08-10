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
        lines.append("  鉴盾 MCPGuard")
        lines.append("  —— 帮你看看装的那些 AI 工具靠不靠谱")
        lines.append("=" * 62)

        total_findings = sum(len(r.findings) for r in results)
        if not results:
            lines.append("\n没找到可以扫描的东西（本机可能没有 MCP 配置或 skill 目录）。")
            lines.append("用 --path 指个目录或文件试试。")
            return "\n".join(lines)

        if total_findings == 0:
            lines.append(f"\n翻了 {len(results)} 个地方，没发现可疑特征。看着挺干净。\n")
        else:
            lines.append(f"\n翻了 {len(results)} 个地方，发现 {total_findings} 处可疑。\n")

        for r in results:
            mark = "[PASS]" if r.score == 100 else ("[WARN]" if r.score >= 70 else "[FAIL]")
            lines.append(f"{mark} [{r.score:3d}/100] {r.target_name}")
            lines.append(f"    类型: {r.kind} | 位置: {_redact(r.path)}")
            if r.findings:
                for f in r.findings:
                    sev = f.severity.upper()
                    lines.append(f"    [x] [{sev}] {f.title} ({f.rule_id})")
                    lines.append(f"        [x] 命中: {_redact(f.excerpt)}")
            lines.append("")

        # 汇总
        lines.append("-" * 62)
        crit = sum(1 for r in results for f in r.findings if f.severity == "critical")
        high = sum(1 for r in results for f in r.findings if f.severity == "high")
        med = sum(1 for r in results for f in r.findings if f.severity == "medium")
        low = sum(1 for r in results for f in r.findings if f.severity == "low")
        info = sum(1 for r in results for f in r.findings if f.severity == "info")
        lines.append(f"  严重 {crit} | 较高 {high} | 中等 {med} | 较低 {low} | 提示 {info}")
        if crit:
            lines.append("")
            lines.append("[!] 有严重级命中：可能是真有投毒指令，")
            lines.append("    也可能只是文档里提了一嘴攻击手法。值得亲手核一下。")
        lines.append("")
        lines.append("分数怎么算的: 100 起步，严重扣 40、较高扣 20、中等扣 8、较低扣 3、提示扣 1。")
        lines.append("  90+ 基本没事 | 70-89 建议看看 | 50-69 有点悬 | <50 得上心。")
        lines.append("  不过分数只是规则命中的结果，不等于真的被攻击，逐条人工确认才算数。")
        lines.append("")
        lines.append("说句实话: 这是关键词规则扫的，可能误报，也防不住玩文字游戏的注入。")
        lines.append("          别拿这份报告当最终结论，高风险项务必自己再确认一遍。")
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

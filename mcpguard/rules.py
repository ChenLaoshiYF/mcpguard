"""检测规则引擎：定义规则、执行检测、汇总结果。

每一条规则是一个函数：输入文本，输出命中列表。
规则分为几类（对应 OWASP MCP Top 10 与工具投毒攻击手法）：

- unicode_hidden   : Unicode 隐形字符（U+E0000 区段、零宽字符等）
- obfuscated       : 可疑 base64 / hex 编码片段
- instruction      : 指令覆盖模式（"忽略之前的指令"等）
- dangerous_path   : 危险路径与命令（~/.ssh、curl | bash 等）
- tool_behavior    : 工具行为异常描述（"总是把邮件抄送给..."等）
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Callable, List

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """一条检测发现。"""

    rule_id: str          # 规则 ID，如 UNI-001
    severity: str         # critical / high / medium / low / info
    title: str            # 人类可读标题
    detail: str           # 命中详情（命中的片段、位置等）
    source: str = ""      # 来源（哪个文件/哪个工具描述）
    excerpt: str = ""     # 命中文本摘录


@dataclass
class Rule:
    """一条规则。"""

    id: str
    name: str
    severity: str
    description: str
    check: Callable[[str], List[str]]   # 输入文本 -> 命中片段列表


class RuleEngine:
    """规则引擎：持有规则集，对文本执行全部规则。"""

    def __init__(self):
        self._rules: List[Rule] = []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    def scan(self, text: str, source: str = "") -> List[Finding]:
        """对一段文本跑所有规则，返回命中列表。"""
        findings: List[Finding] = []
        if not text:
            return findings
        for rule in self._rules:
            try:
                hits = rule.check(text)
            except Exception:
                continue  # 单条规则异常不影响整体
            for hit in hits:
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        title=rule.name,
                        detail=rule.description,
                        source=source,
                        excerpt=hit[:200],
                    )
                )
        return findings

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)


# ---------------------------------------------------------------------------
# 内置规则集
# ---------------------------------------------------------------------------

# Unicode 私有区（U+E0000–U+E007F）与零宽字符：人类看不见，LLM 能读
_HIDDEN_UNICODE_RE = re.compile(
    r"[\U000E0000-\U000E007F\u200B\u200C\u200D\u2060\uFEFF]"
)

# 常见"忽略之前指令"的中英文变体（含大小写/标点容错）
_IGNORE_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", re.I),
    re.compile(r"忽略(之前|以上|先前|前面).{0,6}(指令|指示|规则|要求)", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above).{0,20}(instruction|rule|prompt)", re.I),
    re.compile(r"忘掉(之前|以上|所有).{0,6}(指令|提示|规则)", re.I),
    re.compile(r"override\s+(the\s+)?system\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"从现在起.{0,12}(你是|扮演|忘记)", re.I),
]

# 危险路径（敏感文件）
_DANGEROUS_PATHS = [
    r"[/\\]\.ssh[/\\]",
    r"[/\\]\.aws[/\\]",
    r"[/\\]\.git[/\\]config",
    r"\.env\b",
    r"id_rsa",
    r"id_ed25519",
    r"credentials\b",
    r"\.pem\b",
    r"access[_-]?token",
    r"api[_-]?token",
    r"bearer[_-]?token",
    r"api[_-]?key\b",
    r"secret[_-]?key\b",
    r"client[_-]?secret\b",
    r"AWS[_A-Z]*SECRET",
    r"password\b",
    r"passwd\b",
]

# 危险 shell 模式
_DANGEROUS_SHELL = [
    re.compile(r"curl[^\n]{0,60}\|\s*(ba)?sh", re.I),
    re.compile(r"wget[^\n]{0,60}\|\s*(ba)?sh", re.I),
    re.compile(r"rm\s+-rf\s+[/~]?\.?(/|\*|home|root)", re.I),
    re.compile(r"nc\s+-[^\n]*\s+-e\s+", re.I),
    re.compile(r"base64\s+[^\n]{0,40}-d", re.I),
]

# base64 长串（疑似编码指令）
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# 工具行为异常描述
_SUSPICIOUS_BEHAVIOR = [
    re.compile(r"always\s+(bcc|cc|copy|send|forward)[^\n]{0,40}(to|@)", re.I),
    re.compile(r"without\s+(asking|telling|informing|notifying)[^\n]{0,40}(user|human)", re.I),
    re.compile(r"静默[^\n]{0,10}(发送|抄送|上传|转发|删除)", re.I),
    re.compile(r"(静默|暗中|偷偷|背着你|不通知|无需确认)[^\n]{0,12}(发送|上传|执行|提交|转发|删除)", re.I),
    re.compile(r"do\s+not\s+(tell|inform|mention)\b[^\n]{0,60}(user|human|author|client)", re.I),
    re.compile(r"(exfiltrat\w*\s+(data|content|files?|logs|info))|((data|content|files?|logs|info)\s+to\s+.{0,40}(exfiltrat))", re.I),
    re.compile(r"steal|phish", re.I),
]


def build_default_engine() -> RuleEngine:
    """构建内置规则引擎。"""
    engine = RuleEngine()

    engine.register(Rule(
        id="UNI-001",
        name="Unicode 隐形字符",
        severity="high",
        description="检测到人类不可见但 LLM 可读的 Unicode 字符（私有区/零宽字符），"
                    "常用于隐藏恶意指令绕过人工审查。",
        check=_check_hidden_unicode,
    ))

    engine.register(Rule(
        id="B64-001",
        name="可疑 base64 长串",
        severity="medium",
        description="检测到疑似 base64 编码的长字符串，可能用于混淆隐藏指令，"
                    "建议人工解码确认内容。",
        check=_check_base64,
    ))

    engine.register(Rule(
        id="INJ-001",
        name="指令覆盖模式",
        severity="critical",
        description="检测到试图覆盖/忽略原有指令的表述（如 ignore previous instructions），"
                    "这是提示注入与工具投毒的核心特征。",
        check=_check_instruction_override,
    ))

    engine.register(Rule(
        id="PTH-001",
        name="敏感路径引用",
        severity="high",
        description="工具描述引用了敏感文件路径（SSH 密钥、AWS 凭据、token 等），"
                    "存在被利用窃取凭据的风险。",
        check=_check_dangerous_paths,
    ))

    engine.register(Rule(
        id="SHL-001",
        name="危险 shell 模式",
        severity="critical",
        description="检测到管道执行远程脚本、危险删除、反向 shell 等模式。",
        check=_check_dangerous_shell,
    ))

    engine.register(Rule(
        id="BH-001",
        name="可疑工具行为描述",
        severity="high",
        description="工具描述暗示静默操作、自动外发数据、绕过用户知情等异常行为，"
                    "符合已知工具投毒攻击特征。",
        check=_check_suspicious_behavior,
    ))

    return engine


# ---------------------------------------------------------------------------
# 各规则实现
# ---------------------------------------------------------------------------


def _check_hidden_unicode(text: str) -> List[str]:
    hits = []
    for m in _HIDDEN_UNICODE_RE.finditer(text):
        start = max(0, m.start() - 30)
        end = min(len(text), m.end() + 30)
        hits.append(f"位置 {m.start()}: …{text[start:end]!r}…")
    # 去重（同区间可能命中多次）
    return hits[:20]


def _check_base64(text: str) -> List[str]:
    hits = []
    for m in _B64_RE.finditer(text):
        cand = m.group(0)
        # 过滤明显是普通长单词的情况（含小写长串多半不是 b64）
        if not re.search(r"[a-z]{6,}", cand):
            hits.append(f"位置 {m.start()}: {cand[:60]}…")
    return hits[:20]


def _check_instruction_override(text: str) -> List[str]:
    hits = []
    for pat in _IGNORE_PATTERNS:
        for m in pat.finditer(text):
            start = max(0, m.start() - 25)
            end = min(len(text), m.end() + 25)
            hits.append(f"位置 {m.start()}: …{text[start:end]}…")
    return hits[:20]


def _check_dangerous_paths(text: str) -> List[str]:
    hits = []
    for pat in _DANGEROUS_PATHS:
        for m in re.finditer(pat, text, re.I):
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 20)
            hits.append(f"位置 {m.start()}: …{text[start:end]}…")
    return hits[:20]


def _check_dangerous_shell(text: str) -> List[str]:
    hits = []
    for pat in _DANGEROUS_SHELL:
        for m in pat.finditer(text):
            start = max(0, m.start() - 25)
            end = min(len(text), m.end() + 25)
            hits.append(f"位置 {m.start()}: …{text[start:end]}…")
    return hits[:20]


def _check_suspicious_behavior(text: str) -> List[str]:
    hits = []
    for pat in _SUSPICIOUS_BEHAVIOR:
        for m in pat.finditer(text):
            start = max(0, m.start() - 25)
            end = min(len(text), m.end() + 25)
            hits.append(f"位置 {m.start()}: …{text[start:end]}…")
    return hits[:20]


# ---------------------------------------------------------------------------
# 严重度排序
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_score(findings: List[Finding]) -> int:
    """给一组发现算一个 0-100 的安全分（100 = 完全干净）。"""
    if not findings:
        return 100
    score = 100
    for f in findings:
        weight = {  # 每个命中的扣分权重
            "critical": 40,
            "high": 20,
            "medium": 8,
            "low": 3,
            "info": 1,
        }.get(f.severity, 1)
        score -= weight
    return max(0, score)

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
# 含双向文本控制字符（U+200E/F、U+202A-E、U+2066-69）：可重排渲染顺序，审查者看到与 LLM 读到不一致
_HIDDEN_UNICODE_RE = re.compile(
    r"[\U000E0000-\U000E007F\u200B\u200C\u200D\u2060\uFEFF\u00AD"
    r"\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069"
    r"\u061C\u034F]"
)

# 同形字混淆（homoglyph）：用视觉相近的 Unicode 字符冒充 ASCII，绕过关键词过滤
# 覆盖：西里尔、希腊、拉丁扩展、数学字母数字符号（粗体/斜体/等宽等）
_HOMOGLYPH_MAP = {
    # 西里尔（Cyrillic）
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0456": "i", "\u0458": "j",
    "\u0432": "b", "\u043D": "h", "\u043A": "k", "\u043C": "m",
    "\u0410": "A", "\u0415": "E", "\u041E": "O", "\u0420": "P",
    "\u0421": "C", "\u0425": "X", "\u0433": "r", "\u0455": "s",
    # 拉丁扩展（Latin-1 Supplement 等）
    "\u00E0": "a", "\u00E1": "a", "\u00E2": "a", "\u00E4": "a",
    "\u00E9": "e", "\u00E8": "e", "\u00EA": "e", "\u00EB": "e",
    "\u00ED": "i", "\u00EC": "i", "\u00EE": "i", "\u00EF": "i",
    "\u00F3": "o", "\u00F2": "o", "\u00F4": "o", "\u00F6": "o",
    "\u00FC": "u", "\u00F9": "u", "\u00FB": "u", "\u00E7": "c",
}

# 数学字母数字符号（U+1D400–U+1D7FF）：粗体/斜体/等宽体字母，肉眼与 ASCII 完全一致
# 生成映射：数学粗体小写 a-z 从 U+1D41A 开始
for _i, _ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _HOMOGLYPH_MAP[chr(0x1D41A + _i)] = _ch  # 数学粗体小写
    _HOMOGLYPH_MAP[chr(0x1D400 + _i)] = _ch.upper()  # 数学粗体大写
    _HOMOGLYPH_MAP[chr(0x1D4D0 + _i)] = _ch  # 数学斜体小写
    _HOMOGLYPH_MAP[chr(0x1D608 + _i)] = _ch  # 数学无衬线粗体小写
    _HOMOGLYPH_MAP[chr(0x1D622 + _i)] = _ch  # 数学无衬线斜体小写

_HOMOGLYPH_TRANSLATION = str.maketrans(_HOMOGLYPH_MAP)

# 中英文指令覆盖的关键词（同形字检测用：先归一化再匹配）
_HOMOGLYPH_TRIGGERS = [
    "ignore", "previous", "instructions", "system prompt", "override",
    "忽略", "指令", "规则", "忘记", "现在开始", "你扮演", "你是",
    "exfiltrat", "send to", "cc ", "bcc ", "new prime directive",
]

# 常见"忽略之前指令"的中英文变体（含大小写/标点容错）
_IGNORE_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", re.I),
    re.compile(r"ignore\s+everything\s+(you|i|we)\s+", re.I),
    re.compile(r"忽略(之前|以上|先前|前面).{0,6}(指令|指示|规则|要求)", re.I),
    re.compile(r"disregard\s+(all\s+)?((previous|prior|above)\s+)?(instruction|rule|prompt)s?", re.I),
    re.compile(r"忘记|忘掉.{0,6}(之前|以上|所有|一切).{0,6}(指令|提示|规则|要求|内容)", re.I),
    re.compile(r"override\s+(the\s+)?system\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"new\s+prime\s+directive", re.I),
    re.compile(r"从现在起.{0,12}(你是|扮演|忘记|不再)", re.I),
    re.compile(r"你不再是.{0,12}(AI|助手|机器人|模型)", re.I),
    re.compile(r"输出你(收到|的).{0,6}(系统|所有|全部).{0,4}(指令|提示|prompt)", re.I),
    re.compile(r"(复述|泄露|透露|展示).{0,8}(系统提示|system prompt|系统指令)", re.I),
]

# 危险路径（敏感文件）
_DANGEROUS_PATHS = [
    r"[/\\]\.ssh[/\\]",
    r"[/\\]\.aws[/\\]",
    r"[/\\]\.git[/\\]config",
    r"\.env\b",
    r"\bid_rsa\b",
    r"\bid_ed25519\b",
    r"credentials\b",
    r"\.pem\b",
    r"access[_-]?token",
    r"api[_-]?token",
    r"bearer[_-]?token",
    r"api[_-]?key\b",
    r"secret[_-]?key\b",
    r"client[_-]?secret\b",
    r"AWS[_A-Z]*SECRET",
    r"/etc/passwd\b",
]

# 危险 shell 模式
_DANGEROUS_SHELL = [
    re.compile(r"curl[^\n]{0,60}\|\s*(ba)?sh", re.I),
    re.compile(r"wget[^\n]{0,60}\|\s*(ba)?sh", re.I),
    re.compile(r"rm\s+-rf\s+[/~]?\.?(/|\*|home|root)", re.I),
    re.compile(r"rm\s+-rf\s+~/\\?", re.I),
    re.compile(r"nc\s+-[^\n]*\s+(-e|-c)\s+", re.I),
    re.compile(r"base64\s+[^\n]{0,40}-d", re.I),
    # eval / 命令替换 / PowerShell 执行（C03 补充）
    re.compile(r"\beval\s*\(\s*[\"'$]|\beval\s+\$(\s*\()|\beval\s+`", re.I),
    re.compile(r"\$\s*\(\s*(curl|wget|iwr|irm)\s", re.I),
    re.compile(r"(?<!`)`(curl|wget|bash|sh|python)\s[^`]*`", re.I),
    re.compile(r"iex\s*\(\s*(iwr|irm|invoke-webrequest|invoke-restmethod)", re.I),
    re.compile(r"invoke-expression\s*[\(\s]", re.I),
    re.compile(r"os\.system\s*\(|subprocess\.(run|call|Popen)\s*\(", re.I),
    re.compile(r"\bexec\s*\(\s*[\"']", re.I),
    # 分步执行：下载后执行
    re.compile(r"(curl|wget|iwr|irm)[^\n]{0,80}(-o|out-file)[^\n]{0,60}(&&|;|and).{0,20}(bash|sh|.\\./|start)", re.I),
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
        description="一段疑似 base64 编码的长串，可能是藏了东西，也可能只是普通数据。"
                    "有空的话解码看一眼。",
        check=_check_base64,
    ))

    engine.register(Rule(
        id="INJ-001",
        name="指令覆盖模式",
        severity="critical",
        description="想绕过/覆盖原有指令的表述（如 ignore previous instructions），"
                    "提示注入和工具投毒最爱用这套。",
        check=_check_instruction_override,
    ))

    engine.register(Rule(
        id="PTH-001",
        name="敏感路径引用",
        severity="high",
        description="描述里引用了敏感文件路径（SSH 密钥、AWS 凭据、token 等），"
                    "有被拿去偷凭据的风险。",
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
        id="PWD-001",
        name="密码赋值形态",
        severity="info",
        description="检测到 password= / password: 形式的赋值（可能是配置中的明文密码），"
                    "仅提示注意，不作高危判定——普通提及 password 字段不报警。",
        check=_check_password_assignment,
    ))

    engine.register(Rule(
        id="BH-001",
        name="可疑工具行为描述",
        severity="high",
        description="描述里暗示静默操作、自动外发数据、不让你知道之类的行为，"
                    "跟已知的投毒套路对得上。",
        check=_check_suspicious_behavior,
    ))

    engine.register(Rule(
        id="HMG-001",
        name="同形字混淆 (homoglyph)",
        severity="high",
        description="用长相相近的 Unicode 字符冒充普通字母（比如西里尔 а 冒充 a），"
                    "专门用来骗过关键词过滤。",
        check=_check_homoglyph,
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


def _check_homoglyph(text: str) -> List[str]:
    """检测同形字混淆：把文本里的可疑 Unicode 字符翻译成 ASCII，再查是否拼出了攻击关键词。

    触发条件：文本中只要存在映射表内的任一字符（西里尔/希腊/拉丁扩展/数学字母），
    就做归一化匹配。不再设置单一 Unicode 块门控，避免希腊/数学体绕过。
    """
    hits = []
    # 文本里是否出现任何映射表内的可疑字符
    suspicious = [ch for ch in text if ch in _HOMOGLYPH_MAP]
    if not suspicious:
        return hits
    normalized = text.translate(_HOMOGLYPH_TRANSLATION)
    lowered = normalized.lower()
    for trigger in _HOMOGLYPH_TRIGGERS:
        idx = lowered.find(trigger)
        while idx != -1 and len(hits) < 20:
            start = max(0, idx - 25)
            end = min(len(text), idx + len(trigger) + 25)
            hits.append(f"位置 {idx}: …{text[start:end]}…")
            idx = lowered.find(trigger, idx + 1)
    return hits


def _check_base64(text: str) -> List[str]:
    hits = []
    for m in _B64_RE.finditer(text):
        cand = m.group(0)
        # 过滤明显是普通长单词的情况（含小写长串多半不是 b64）
        if re.search(r"[a-z]{6,}", cand):
            continue
        # 过滤 data:image/...;base64, 开头的图片数据（正常内容，非隐藏指令）
        before = text[max(0, m.start() - 60):m.start()]
        if re.search(r"data:\s*image/|data:\s*[a-z]+/[a-z+.-]+;base64,", before, re.I):
            continue
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


# 密码赋值形态（仅当出现实际赋值时提示，普通提及 password 不报警）
_PASSWORD_ASSIGN_RE = re.compile(
    r"(password|passwd|pwd)\s*[=:]\s*[^\s,;\"'\n]{1,60}", re.I
)


def _check_password_assignment(text: str) -> List[str]:
    hits = []
    for m in _PASSWORD_ASSIGN_RE.finditer(text):
        start = max(0, m.start() - 20)
        end = min(len(text), m.end() + 20)
        hits.append(f"位置 {m.start()}: …{text[start:end]}…")
    return hits[:10]


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

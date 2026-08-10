# -*- coding: utf-8 -*-
"""修正 _DANGEROUS_PATHS 中的双反斜杠问题。"""
import io

path = "mcpguard/rules.py"
src = io.open(path, encoding="utf-8").read()

# 找出当前块并重写为正确的单反斜杠转义
start_marker = "_DANGEROUS_PATHS = ["
end_marker = "]\n\n# 危险 shell 模式"

i_start = src.find(start_marker)
i_end = src.find(end_marker) + len(end_marker)
if i_start == -1 or i_end == -1:
    print(f"定位失败: start={i_start} end={i_end}")
    raise SystemExit(1)

new_block = '''_DANGEROUS_PATHS = [
    r"[/\\\\]\\.ssh[/\\\\]",
    r"[/\\\\]\\.aws[/\\\\]",
    r"[/\\\\]\\.git[/\\\\]config",
    r"\\.env\\b",
    r"\\bid_rsa\\b",
    r"\\bid_ed25519\\b",
    r"credentials\\b",
    r"\\.pem\\b",
    r"access[_-]?token",
    r"api[_-]?token",
    r"bearer[_-]?token",
    r"api[_-]?key\\b",
    r"secret[_-]?key\\b",
    r"client[_-]?secret\\b",
    r"AWS[_A-Z]*SECRET",
    r"/etc/passwd\\b",
]

# 危险 shell 模式'''

src = src[:i_start] + new_block + src[i_end:]
io.open(path, "w", encoding="utf-8").write(src)
print("修正完成")

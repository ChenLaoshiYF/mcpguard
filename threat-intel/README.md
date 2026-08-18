# 明棱威胁情报语料库 (MCPGuard Threat Corpus)

> MCP 工具投毒检测语料库：验证规则引擎的正负样本集合。

## 安全声明

**本语料库所有条目均为纯文本字符串，仅用于检测规则匹配与安全研究。**

- 标注 `danger: executable-shell` 的条目包含可执行命令文本，**严禁执行/eval**
- 所有样本仅作正则匹配测试，任何环境中都不得运行其内容
- 采用 dual-use 处理：公开规则与特征描述，不收录完整可执行 payload

## 用途

- **规则引擎回归测试**：每条正样本必须被至少一条规则命中
- **零误报验证**：每条负样本（clean control）不应命中任何规则
- **安全研究参考**：投毒手法的结构化分类

## 结构

| 字段 | 说明 |
|------|------|
| `text` | 样本内容（纯文本） |
| `category` | `positive-poison-sample` / `negative-clean-control` |
| `danger` | `executable-shell`（含可执行命令）/ `text-only` |
| `source` | 样本来源 |
| `note` | 说明 |

## 验证方式

```bash
# 在 mcpguard 项目内
python -c "
import json, io
from mcpguard.rules import build_default_engine
corpus = json.load(io.open('threat-intel/corpus_v1.json', encoding='utf-8'))
engine = build_default_engine()
for s in corpus['samples']:
    findings = engine.scan(s['text'], source='corpus')
    if s['category'].startswith('positive') and not findings:
        print('MISS:', s['text'][:40])
    if s['category'].startswith('negative') and findings:
        print('FP:', s['text'][:40])
print('done')
"
```

## 版本

- v1 (2026-08): 25 条样本（22 正 + 3 负），源自 mcpguard selftest 验证用例

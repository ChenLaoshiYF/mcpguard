"""鉴盾 (MCPGuard) - 本地 AI Agent 安全扫描器。

扫描本机 MCP server 配置与 skill 目录，检测工具描述中的投毒特征
（Unicode 隐形字符、可疑 base64、指令覆盖模式、危险路径等），
输出安全评分与风险报告。全部本地运行，数据不出机器。
"""

__version__ = "0.1.0"

"""扫描器：定位本机 MCP 配置、skill 目录，提取待检测文本。

支持的扫描对象：
1. MCP 配置文件（Claude Desktop、Claude Code、Cursor 等常见位置）
2. skill 目录下的所有文本文件（.md / .txt / .yaml / .yml / .json）
3. 用户指定路径

提取规则：
- MCP 配置：抓取每个 server 的 command/args/env 以及 url
- skill 文件：读取文件全文（限制大小防止超大文件拖慢）
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# 常见 MCP 配置文件位置（按平台）
_MCP_CONFIG_CANDIDATES = [
    # Claude Desktop (Windows)
    r"%APPDATA%\Claude\claude_desktop_config.json",
    # Claude Desktop (macOS)
    r"~/Library/Application Support/Claude/claude_desktop_config.json",
    # Claude Code (Windows)
    r"%USERPROFILE%\.claude.json",
    # Cursor (Windows)
    r"%APPDATA%\Cursor\User\globalStorage\storage.json",
    # 通用 .mcp.json（项目级）
    r".mcp.json",
]

_SKILL_FILE_EXTS = {".md", ".txt", ".yaml", ".yml", ".json", ".toml"}
_MAX_FILE_BYTES = 256 * 1024  # 单文件上限 256KB


@dataclass
class ScanTarget:
    """一个待检测目标。"""

    kind: str            # "mcp_config" / "skill_file" / "explicit"
    name: str            # 展示名（如 "Claude Desktop 配置" / 文件名）
    path: str            # 绝对路径
    content: str         # 提取出的文本内容
    extra: Dict = field(default_factory=dict)  # 附加信息（如 server 名）


class Scanner:
    """扫描本机 AI Agent 相关配置与 skill 文件。"""

    def __init__(self, extra_paths: Optional[List[str]] = None):
        self.extra_paths = extra_paths or []
        self._targets: List[ScanTarget] = []

    # ------------------------------------------------------------------
    # 入口
    # ------------------------------------------------------------------
    def scan_all(self) -> List[ScanTarget]:
        """扫描所有可定位的目标。"""
        self._targets = []
        self._scan_mcp_configs()
        self._scan_skill_dirs()
        self._scan_explicit_paths()
        return self._targets

    # ------------------------------------------------------------------
    # MCP 配置
    # ------------------------------------------------------------------
    def _scan_mcp_configs(self) -> None:
        for raw in _MCP_CONFIG_CANDIDATES:
            path = self._expand_path(raw)
            if path and path.is_file():
                self._extract_mcp_config(path)

    def _extract_mcp_config(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return  # 非 JSON 或损坏，跳过
        servers = self._find_servers(data)
        for name, server in servers.items():
            text = self._server_to_text(name, server)
            self._targets.append(
                ScanTarget(
                    kind="mcp_config",
                    name=f"MCP server「{name}」",
                    path=str(path),
                    content=text,
                    extra={"server_name": name, "config_path": str(path)},
                )
            )

    @staticmethod
    def _find_servers(data: dict) -> Dict[str, dict]:
        """从配置 JSON 里挖出所有 MCP server 定义。"""
        servers: Dict[str, dict] = {}
        # 常见结构: { "mcpServers": { name: {...} } }
        if isinstance(data, dict):
            for key in ("mcpServers", "mcp_servers", "servers"):
                val = data.get(key)
                if isinstance(val, dict):
                    for name, cfg in val.items():
                        if isinstance(cfg, dict):
                            servers[name] = cfg
            # 结构: { "enableMcpServers": { name: true } } 或嵌套其他
            for key in ("enableMcpServers", "disabledMcpServers"):
                val = data.get(key)
                if isinstance(val, dict):
                    for name in val:
                        if name not in servers:
                            servers[name] = {}
        return servers

    @staticmethod
    def _server_to_text(name: str, server: dict) -> str:
        """把一个 server 配置转成可检测的文本。"""
        parts = [f"server: {name}"]
        for key in ("command", "url", "name", "description"):
            val = server.get(key)
            if isinstance(val, str) and val:
                parts.append(f"{key}: {val}")
        args = server.get("args")
        if isinstance(args, list):
            parts.append("args: " + " ".join(str(a) for a in args))
        env = server.get("env")
        if isinstance(env, dict):
            # 环境变量里可能有密钥。**只取键名，不取值**，避免把真实 token 带进报告。
            # 检测器仍能通过键名（如 API_KEY）发现可疑配置，但值绝不落盘/落报告。
            safe_env = {k: "***" for k in env.keys()}
            parts.append("env_keys: " + json.dumps(safe_env, ensure_ascii=False))
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # skill 目录
    # ------------------------------------------------------------------
    def _scan_skill_dirs(self) -> None:
        """扫描常见 skill 目录。"""
        home = Path.home()
        candidates = [
            home / ".claude" / "skills",
            home / ".hanako" / "skills",
            home / ".cursor" / "skills",
            home / ".config" / "skills",
        ]
        for d in candidates:
            if d.is_dir():
                self._scan_dir(d)

    def _scan_dir(self, root: Path) -> None:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in _SKILL_FILE_EXTS:
                continue
            try:
                if p.stat().st_size > _MAX_FILE_BYTES:
                    continue
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if not content.strip():
                continue
            rel = p.relative_to(root)
            self._targets.append(
                ScanTarget(
                    kind="skill_file",
                    name=str(rel),
                    path=str(p),
                    content=content,
                )
            )

    # ------------------------------------------------------------------
    # 显式路径
    # ------------------------------------------------------------------
    def _scan_explicit_paths(self) -> None:
        for raw in self.extra_paths:
            path = Path(raw).expanduser().resolve()
            if path.is_dir():
                self._scan_dir(path)
            elif path.is_file():
                self._scan_file(path)

    def _scan_file(self, path: Path) -> None:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return
        self._targets.append(
            ScanTarget(kind="explicit", name=path.name, path=str(path), content=content)
        )

    # ------------------------------------------------------------------
    # 工具
    # ------------------------------------------------------------------
    @staticmethod
    def _expand_path(raw: str) -> Optional[Path]:
        """展开 %VAR% 与 ~ 为绝对路径。"""
        expanded = os.path.expandvars(os.path.expanduser(raw))
        p = Path(expanded)
        return p if p.exists() else None

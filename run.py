"""PyInstaller 打包入口：在包外调用 mcpguard，保证相对导入正常。

用法: pyinstaller --onefile --name mcpguard run.py
"""

import sys

from mcpguard.cli import main

if __name__ == "__main__":
    sys.exit(main())

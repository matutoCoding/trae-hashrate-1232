#!/usr/bin/env python3
"""共享文件夹权限审计工具入口脚本"""

import sys

from audit_tool.cli import audit_main

if __name__ == "__main__":
    sys.exit(audit_main())

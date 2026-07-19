#!/usr/bin/env pythonw
# -*- coding: utf-8 -*-
"""Windows no-console launcher for node-stable.py.

Keep this file, node-stable.py and config.json in the same directory.
The network core, Web UI and Windows tray are implemented in node-stable.py;
this launcher only starts it through pythonw.exe without a console window.
"""

from __future__ import annotations

import ctypes
import importlib.util
import sys
import traceback
from pathlib import Path


def show_error(title: str, message: str) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            str(message),
            str(title),
            0x00000010 | 0x00010000 | 0x00040000,
        )
    except Exception:
        pass


def main() -> int:
    base = Path(__file__).resolve().parent
    target = base / "node-stable.py"
    if not target.is_file():
        show_error(
            "P2P Tunnel 启动失败",
            f"未找到核心文件：\n{target}\n\n请将 node-stable.py、node-stable-windows.pyw 和 config.json 放在同一目录。",
        )
        return 1

    try:
        spec = importlib.util.spec_from_file_location("p2p_node_stable_core", target)
        if spec is None or spec.loader is None:
            raise ImportError(f"无法加载 {target}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        entry = getattr(module, "bootstrap", None)
        if not callable(entry):
            raise AttributeError("node-stable.py 缺少 bootstrap() 入口")
        return int(entry())
    except SystemExit as exc:
        return int(exc.code or 0)
    except BaseException as exc:
        detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        show_error(
            "P2P Tunnel 启动失败",
            f"{type(exc).__name__}: {exc}\n\n详细信息：\n{detail[-6000:]}",
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

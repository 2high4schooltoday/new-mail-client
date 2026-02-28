from __future__ import annotations

import curses


KEY_ENTER = {10, 13, curses.KEY_ENTER}
KEY_BACK = {curses.KEY_BACKSPACE, 127, 8}


def is_enter(key: object) -> bool:
    return isinstance(key, int) and key in KEY_ENTER or key == "\n"


def is_backspace(key: object) -> bool:
    return isinstance(key, int) and key in KEY_BACK

from __future__ import annotations

import curses


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def safe_addstr(stdscr: curses.window, y: int, x: int, text: str, attr: int = 0) -> None:
    h, w = stdscr.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    if x < 0:
        text = text[-x:]
        x = 0
    if not text:
        return
    max_len = max(0, w - x - 1)
    if max_len <= 0:
        return
    try:
        stdscr.addnstr(y, x, text, max_len, attr)
    except curses.error:
        pass


def safe_addch(stdscr: curses.window, y: int, x: int, ch: int, attr: int = 0) -> None:
    h, w = stdscr.getmaxyx()
    if 0 <= y < h and 0 <= x < w:
        try:
            stdscr.addch(y, x, ch, attr)
        except curses.error:
            pass


def draw_box(stdscr: curses.window, y: int, x: int, h: int, w: int, title: str = "", attr: int = 0) -> None:
    if h < 2 or w < 2:
        return
    safe_addch(stdscr, y, x, curses.ACS_ULCORNER, attr)
    safe_addch(stdscr, y, x + w - 1, curses.ACS_URCORNER, attr)
    safe_addch(stdscr, y + h - 1, x, curses.ACS_LLCORNER, attr)
    safe_addch(stdscr, y + h - 1, x + w - 1, curses.ACS_LRCORNER, attr)
    for xx in range(x + 1, x + w - 1):
        safe_addch(stdscr, y, xx, curses.ACS_HLINE, attr)
        safe_addch(stdscr, y + h - 1, xx, curses.ACS_HLINE, attr)
    for yy in range(y + 1, y + h - 1):
        safe_addch(stdscr, yy, x, curses.ACS_VLINE, attr)
        safe_addch(stdscr, yy, x + w - 1, curses.ACS_VLINE, attr)
    if title:
        safe_addstr(stdscr, y, x + 2, f" {title} ", attr)


def progress_bar(width: int, ratio: float) -> str:
    width = max(1, width)
    ratio = max(0.0, min(1.0, ratio))
    fill = int(round(width * ratio))
    return "[" + ("#" * fill).ljust(width, "-") + "]"


def spinner(tick: int) -> str:
    frames = ["|", "/", "-", "\\"]
    return frames[tick % len(frames)]

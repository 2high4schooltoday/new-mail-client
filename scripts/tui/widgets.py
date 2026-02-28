from __future__ import annotations

import curses
from dataclasses import dataclass

from .theme import Theme
from .views import clamp, progress_bar, safe_addstr


@dataclass(frozen=True)
class Rect:
    y: int
    x: int
    h: int
    w: int
    action: str

    def contains(self, y: int, x: int) -> bool:
        return self.y <= y < self.y + self.h and self.x <= x < self.x + self.w


def draw_button(
    stdscr: curses.window,
    theme: Theme,
    y: int,
    x: int,
    label: str,
    *,
    focused: bool = False,
    primary: bool = False,
    danger: bool = False,
    disabled: bool = False,
    action: str = "",
) -> Rect:
    text = f"[ {label} ]"
    if disabled:
        attr = theme.attrs.button_disabled
    elif focused:
        attr = theme.attrs.focus
    elif primary:
        attr = theme.attrs.button_primary
    elif danger:
        attr = theme.attrs.button_danger
    else:
        attr = theme.attrs.button
    safe_addstr(stdscr, y, x, text, attr)
    return Rect(y=y, x=x, h=1, w=len(text), action=action)


def draw_toggle(
    stdscr: curses.window,
    theme: Theme,
    y: int,
    x: int,
    enabled: bool,
    *,
    focused: bool = False,
    action: str = "",
) -> Rect:
    label = "Enabled" if enabled else "Disabled"
    attr = theme.attrs.primary if enabled else theme.attrs.muted
    if focused:
        attr = theme.attrs.focus
    text = f"[ {label} ]"
    safe_addstr(stdscr, y, x, text, attr)
    return Rect(y=y, x=x, h=1, w=len(text), action=action)


def draw_segmented(
    stdscr: curses.window,
    theme: Theme,
    y: int,
    x: int,
    options: list[str],
    selected: int,
    focused_idx: int,
    prefix: str,
) -> list[Rect]:
    rects: list[Rect] = []
    col = x
    for idx, opt in enumerate(options):
        focused = idx == focused_idx
        primary = idx == selected
        rect = draw_button(
            stdscr,
            theme,
            y,
            col,
            opt,
            focused=focused,
            primary=primary,
            action=f"{prefix}:{idx}",
        )
        rects.append(rect)
        col += rect.w + 1
    return rects


def draw_meter(
    stdscr: curses.window,
    theme: Theme,
    y: int,
    x: int,
    width: int,
    ratio: float,
    label: str,
) -> None:
    bar_w = max(12, width - len(label) - 7)
    bar = progress_bar(bar_w, ratio)
    pct = f"{int(clamp(int(ratio * 100), 0, 100)):3d}%"
    safe_addstr(stdscr, y, x, f"{label} {bar} {pct}", theme.attrs.info)


def draw_badge(stdscr: curses.window, theme: Theme, y: int, x: int, text: str, kind: str = "info") -> None:
    attr = theme.attrs.info
    if kind == "warning":
        attr = theme.attrs.warning
    elif kind == "error":
        attr = theme.attrs.error
    elif kind == "primary":
        attr = theme.attrs.primary
    elif kind == "success":
        attr = theme.attrs.success
    safe_addstr(stdscr, y, x, f"[{text}]", attr)

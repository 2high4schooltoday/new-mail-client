from __future__ import annotations

import curses
import textwrap
from dataclasses import dataclass, field
from typing import Any

from .glyphs import Glyphs, current_glyphs, smooth_bar_parts
from .theme import Theme
from .views import safe_addch, safe_addstr


@dataclass
class BufferSurface:
    width: int
    height: int
    chars: list[list[str]] = field(init=False)
    styles: list[list[str]] = field(init=False)

    def __post_init__(self) -> None:
        self.chars = [[" " for _ in range(self.width)] for _ in range(self.height)]
        self.styles = [["panel" for _ in range(self.width)] for _ in range(self.height)]

    def text(self, y: int, x: int, text: str, style: str = "panel") -> None:
        if y < 0 or y >= self.height or x >= self.width:
            return
        col = max(0, x)
        for ch in text[max(0, -x) :]:
            if col >= self.width:
                break
            self.chars[y][col] = ch
            self.styles[y][col] = style
            col += 1

    def fill(self, y: int, x: int, h: int, w: int, ch: str = " ", style: str = "panel") -> None:
        for yy in range(max(0, y), min(self.height, y + h)):
            for xx in range(max(0, x), min(self.width, x + w)):
                self.chars[yy][xx] = ch
                self.styles[yy][xx] = style

    def hline(self, y: int, x: int, w: int, ch: str, style: str = "panel") -> None:
        if y < 0 or y >= self.height:
            return
        for xx in range(max(0, x), min(self.width, x + max(0, w))):
            self.chars[y][xx] = ch
            self.styles[y][xx] = style

    def vline(self, y: int, x: int, h: int, ch: str, style: str = "panel") -> None:
        if x < 0 or x >= self.width:
            return
        for yy in range(max(0, y), min(self.height, y + max(0, h))):
            self.chars[yy][x] = ch
            self.styles[yy][x] = style

    def box(self, y: int, x: int, h: int, w: int, glyphs: Glyphs | None = None, style: str = "panel") -> None:
        glyphs = glyphs or current_glyphs()
        if h < 2 or w < 2:
            return
        self.text(y, x, glyphs.box_tl, style)
        self.text(y, x + w - 1, glyphs.box_tr, style)
        self.text(y + h - 1, x, glyphs.box_bl, style)
        self.text(y + h - 1, x + w - 1, glyphs.box_br, style)
        self.hline(y, x + 1, w - 2, glyphs.box_h, style)
        self.hline(y + h - 1, x + 1, w - 2, glyphs.box_h, style)
        self.vline(y + 1, x, h - 2, glyphs.box_v, style)
        self.vline(y + 1, x + w - 1, h - 2, glyphs.box_v, style)

    def render(self) -> list[str]:
        return ["".join(row) for row in self.chars]


class CursesSurface:
    def __init__(self, stdscr: curses.window, theme: Theme) -> None:
        self.stdscr = stdscr
        self.theme = theme
        self.height, self.width = stdscr.getmaxyx()

    def text(self, y: int, x: int, text: str, style: str = "panel") -> None:
        safe_addstr(self.stdscr, y, x, text, self._attr(style))

    def fill(self, y: int, x: int, h: int, w: int, ch: str = " ", style: str = "panel") -> None:
        if w <= 0 or h <= 0:
            return
        line = ch * max(0, w)
        for yy in range(y, y + h):
            safe_addstr(self.stdscr, yy, x, line, self._attr(style))

    def hline(self, y: int, x: int, w: int, ch: str, style: str = "panel") -> None:
        if w <= 0:
            return
        safe_addstr(self.stdscr, y, x, ch * w, self._attr(style))

    def vline(self, y: int, x: int, h: int, ch: str, style: str = "panel") -> None:
        if h <= 0:
            return
        code = ord(ch[:1]) if ch else ord(" ")
        for yy in range(y, y + h):
            safe_addch(self.stdscr, yy, x, code, self._attr(style))

    def box(self, y: int, x: int, h: int, w: int, glyphs: Glyphs | None = None, style: str = "panel") -> None:
        glyphs = glyphs or current_glyphs()
        if h < 2 or w < 2:
            return
        self.text(y, x, glyphs.box_tl, style)
        self.text(y, x + w - 1, glyphs.box_tr, style)
        self.text(y + h - 1, x, glyphs.box_bl, style)
        self.text(y + h - 1, x + w - 1, glyphs.box_br, style)
        self.hline(y, x + 1, w - 2, glyphs.box_h, style)
        self.hline(y + h - 1, x + 1, w - 2, glyphs.box_h, style)
        self.vline(y + 1, x, h - 2, glyphs.box_v, style)
        self.vline(y + 1, x + w - 1, h - 2, glyphs.box_v, style)

    def _attr(self, style: str) -> int:
        return getattr(self.theme.attrs, style, self.theme.attrs.panel)


@dataclass(frozen=True)
class LayoutTier:
    name: str
    rail_w: int
    body_pad_x: int
    body_pad_y: int
    footer_h: int
    title_h: int
    log_h: int


def choose_layout(width: int, height: int) -> LayoutTier:
    if width >= 110 and height >= 30:
        return LayoutTier("full", rail_w=30, body_pad_x=4, body_pad_y=2, footer_h=4, title_h=4, log_h=11)
    return LayoutTier("compact", rail_w=24, body_pad_x=3, body_pad_y=1, footer_h=4, title_h=4, log_h=8)


def wrap_paragraph(text: str, width: int) -> list[str]:
    val = " ".join((text or "").split())
    if not val:
        return []
    return textwrap.wrap(val, width=max(8, width)) or [val[: max(1, width)]]


def wrap_value(text: Any, width: int) -> list[str]:
    raw = str(text or "")
    if not raw:
        return [""]
    width = max(8, width)
    wrapped: list[str] = []
    for part in raw.splitlines() or [raw]:
        pieces = textwrap.wrap(
            part,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
            replace_whitespace=False,
            drop_whitespace=False,
        )
        wrapped.extend(pieces or [part[:width]])
    return wrapped or [raw[:width]]


def ellipsis_clip(text: Any, width: int, glyphs: Glyphs | None = None) -> str:
    width = max(0, int(width))
    if width <= 0:
        return ""
    glyphs = glyphs or current_glyphs()
    raw = " ".join(str(text or "").split())
    if len(raw) <= width:
        return raw
    ellipsis = glyphs.ellipsis
    if width <= len(ellipsis):
        return ellipsis[:width]
    return raw[: width - len(ellipsis)] + ellipsis


def titled_rule(
    surface: BufferSurface | CursesSurface,
    y: int,
    x: int,
    w: int,
    title: str,
    glyphs: Glyphs | None = None,
    *,
    line_style: str = "chrome",
    title_style: str = "rail",
) -> int:
    if w <= 0:
        return y
    glyphs = glyphs or current_glyphs()
    label = f" {ellipsis_clip(title, max(1, w - 2), glyphs)} "
    surface.text(y, x, label[:w], title_style)
    rem_x = x + len(label)
    if rem_x < x + w:
        surface.hline(y, rem_x, (x + w) - rem_x, glyphs.box_h, line_style)
    return y + 1


def section_heading(
    surface: BufferSurface | CursesSurface,
    y: int,
    x: int,
    w: int,
    title: str,
    summary: str = "",
    *,
    glyphs: Glyphs | None = None,
) -> int:
    surface.text(y, x, ellipsis_clip(title, w, glyphs), "heading")
    row = y + 1
    if summary:
        for line in wrap_paragraph(summary, max(8, w)):
            surface.text(row + 1, x, line, "panel")
            row += 1
        row += 1
    return row + 1


def soft_panel(
    surface: BufferSurface | CursesSurface,
    y: int,
    x: int,
    w: int,
    lines: list[str],
    *,
    glyphs: Glyphs | None = None,
    title: str = "",
    line_style: str = "muted",
    title_style: str = "rail",
) -> int:
    glyphs = glyphs or current_glyphs()
    row = y
    if title:
        row = titled_rule(surface, row, x, w, title, glyphs, title_style=title_style)
    content_w = max(8, w - 4)
    for line in lines:
        wrapped = wrap_paragraph(line, content_w)
        for idx, segment in enumerate(wrapped):
            prefix = f"{glyphs.bullet} " if idx == 0 else "  "
            surface.text(row, x, prefix, "rail")
            surface.text(row, x + 2, segment[:content_w], line_style)
            row += 1
    return row


def key_value_row(
    surface: BufferSurface | CursesSurface,
    y: int,
    x: int,
    w: int,
    label: str,
    value: Any,
    *,
    glyphs: Glyphs | None = None,
    label_w: int = 24,
    label_style: str = "muted",
    value_style: str = "panel",
    focused: bool = False,
) -> int:
    glyphs = glyphs or current_glyphs()
    marker_x = x
    label_x = x + 2
    label_w = min(max(10, label_w), max(10, w - 12))
    gap = 3
    value_x = label_x + label_w + gap
    value_w = max(8, w - (value_x - x))
    marker = glyphs.marker if focused else " "
    marker_style = "primary" if focused else "panel"
    surface.text(y, marker_x, marker, marker_style)
    surface.text(y, label_x, ellipsis_clip(label, label_w, glyphs), label_style)
    lines = wrap_value(value, value_w)
    for idx, segment in enumerate(lines):
        surface.text(y + idx, value_x, segment[:value_w], value_style)
    return len(lines)


def progress_bar(
    surface: BufferSurface | CursesSurface,
    y: int,
    x: int,
    w: int,
    ratio: float,
    *,
    glyphs: Glyphs | None = None,
    fill_style: str = "primary",
    empty_style: str = "rail",
) -> None:
    glyphs = glyphs or current_glyphs()
    filled, empty = smooth_bar_parts(w, ratio, glyphs)
    if filled:
        surface.text(y, x, filled, fill_style)
    if empty:
        surface.text(y, x + len(filled), empty, empty_style)

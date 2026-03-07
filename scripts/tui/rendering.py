from __future__ import annotations

import curses
import textwrap
from dataclasses import dataclass, field

from .glyphs import Glyphs, current_glyphs
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
        return LayoutTier("full", rail_w=30, body_pad_x=4, body_pad_y=2, footer_h=4, title_h=3, log_h=11)
    return LayoutTier("compact", rail_w=24, body_pad_x=3, body_pad_y=1, footer_h=4, title_h=3, log_h=8)


def wrap_paragraph(text: str, width: int) -> list[str]:
    val = " ".join((text or "").split())
    if not val:
        return []
    return textwrap.wrap(val, width=max(8, width)) or [val[: max(1, width)]]

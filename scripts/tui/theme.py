from __future__ import annotations

import curses
from dataclasses import dataclass


@dataclass(frozen=True)
class ThemeAttrs:
    panel: int
    heading: int
    muted: int
    primary: int
    warning: int
    error: int
    info: int
    success: int
    focus: int
    button: int
    button_primary: int
    button_danger: int
    button_disabled: int


class Theme:
    def __init__(self, has_color: bool) -> None:
        self.has_color = has_color
        self.attrs = ThemeAttrs(
            panel=0,
            heading=curses.A_BOLD,
            muted=curses.A_DIM,
            primary=curses.A_BOLD,
            warning=curses.A_BOLD,
            error=curses.A_BOLD,
            info=0,
            success=curses.A_BOLD,
            focus=curses.A_REVERSE,
            button=0,
            button_primary=curses.A_BOLD,
            button_danger=curses.A_BOLD,
            button_disabled=curses.A_DIM,
        )

    @classmethod
    def init(cls) -> "Theme":
        has_color = curses.has_colors()
        theme = cls(has_color=has_color)
        if not has_color:
            return theme

        curses.start_color()
        curses.use_default_colors()

        # Warm palette: mustard / rust / crimson oriented semantics.
        curses.init_pair(1, curses.COLOR_WHITE, -1)   # neutral
        curses.init_pair(2, curses.COLOR_YELLOW, -1)  # mustard
        curses.init_pair(3, curses.COLOR_RED, -1)     # crimson/error
        curses.init_pair(4, curses.COLOR_MAGENTA, -1) # rust-ish fallback
        curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_YELLOW)  # focused
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_RED)     # primary btn
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_WHITE)   # button base

        theme.attrs = ThemeAttrs(
            panel=curses.color_pair(1),
            heading=curses.color_pair(2) | curses.A_BOLD,
            muted=curses.A_DIM,
            primary=curses.color_pair(3) | curses.A_BOLD,
            warning=curses.color_pair(2) | curses.A_BOLD,
            error=curses.color_pair(3) | curses.A_BOLD,
            info=curses.color_pair(4),
            success=curses.color_pair(1) | curses.A_BOLD,
            focus=curses.color_pair(5) | curses.A_BOLD,
            button=curses.color_pair(7),
            button_primary=curses.color_pair(6) | curses.A_BOLD,
            button_danger=curses.color_pair(3) | curses.A_BOLD,
            button_disabled=curses.A_DIM,
        )
        return theme

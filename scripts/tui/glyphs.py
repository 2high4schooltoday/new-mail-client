from __future__ import annotations

import locale
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Glyphs:
    unicode: bool
    box_h: str
    box_v: str
    box_tl: str
    box_tr: str
    box_bl: str
    box_br: str
    divider_left: str
    divider_right: str
    bullet: str
    bullet_active: str
    bullet_done: str
    bullet_pending: str
    marker: str
    shade_light: str
    shade_mid: str
    shade_dark: str
    ellipsis: str
    card_on: str
    card_off: str


UNICODE_GLYPHS = Glyphs(
    unicode=True,
    box_h="─",
    box_v="│",
    box_tl="╭",
    box_tr="╮",
    box_bl="╰",
    box_br="╯",
    divider_left="├",
    divider_right="┤",
    bullet="•",
    bullet_active="◉",
    bullet_done="●",
    bullet_pending="○",
    marker="▎",
    shade_light="░",
    shade_mid="▒",
    shade_dark="▓",
    ellipsis="…",
    card_on="◈",
    card_off="◇",
)

ASCII_GLYPHS = Glyphs(
    unicode=False,
    box_h="-",
    box_v="|",
    box_tl="+",
    box_tr="+",
    box_bl="+",
    box_br="+",
    divider_left="+",
    divider_right="+",
    bullet="*",
    bullet_active="@",
    bullet_done="o",
    bullet_pending="o",
    marker=">",
    shade_light=".",
    shade_mid=":",
    shade_dark="#",
    ellipsis="...",
    card_on="[*]",
    card_off="[ ]",
)

_BLOCKS = "▏▎▍▌▋▊▉█"


def unicode_enabled() -> bool:
    if os.environ.get("DESPATCH_TUI_ASCII", "").strip() == "1":
        return False
    env = " ".join(
        filter(
            None,
            [
                os.environ.get("LC_ALL", ""),
                os.environ.get("LC_CTYPE", ""),
                os.environ.get("LANG", ""),
                locale.getpreferredencoding(False),
            ],
        )
    ).upper()
    return "UTF-8" in env or "UTF8" in env


def current_glyphs() -> Glyphs:
    return UNICODE_GLYPHS if unicode_enabled() else ASCII_GLYPHS


def smooth_bar(width: int, ratio: float, glyphs: Glyphs | None = None) -> str:
    glyphs = glyphs or current_glyphs()
    width = max(1, int(width))
    ratio = max(0.0, min(1.0, float(ratio)))
    if not glyphs.unicode:
        fill = int(round(width * ratio))
        return "[" + ("#" * fill).ljust(width, "-") + "]"

    total_units = int(round(width * 8 * ratio))
    full = total_units // 8
    rem = total_units % 8
    out = []
    for idx in range(width):
        if idx < full:
            out.append(_BLOCKS[-1])
        elif idx == full and rem:
            out.append(_BLOCKS[rem - 1])
        else:
            out.append(glyphs.shade_light)
    return "".join(out)


def smooth_bar_parts(width: int, ratio: float, glyphs: Glyphs | None = None) -> tuple[str, str]:
    glyphs = glyphs or current_glyphs()
    width = max(1, int(width))
    ratio = max(0.0, min(1.0, float(ratio)))
    if not glyphs.unicode:
        fill = int(round(width * ratio))
        return "#" * fill, glyphs.box_h * max(0, width - fill)

    total_units = int(round(width * 8 * ratio))
    full = total_units // 8
    rem = total_units % 8
    filled: list[str] = []
    for _ in range(min(width, full)):
        filled.append(_BLOCKS[-1])
    if full < width and rem:
        filled.append(_BLOCKS[rem - 1])
    fill_text = "".join(filled)
    empty_text = glyphs.box_h * max(0, width - len(fill_text))
    return fill_text, empty_text


def step_glyph(status: str, *, active: bool, glyphs: Glyphs | None = None) -> str:
    glyphs = glyphs or current_glyphs()
    normalized = (status or "pending").lower()
    if normalized in {"ok", "done"}:
        return glyphs.bullet_done
    if normalized in {"failed", "error"}:
        return "!" if not glyphs.unicode else "✕"
    if active or normalized == "running":
        return glyphs.bullet_active
    if normalized == "skipped":
        return "-"
    return glyphs.bullet_pending


def braille_texture(width: int, height: int, glyphs: Glyphs | None = None) -> list[str]:
    glyphs = glyphs or current_glyphs()
    width = max(4, width)
    height = max(3, height)
    if not glyphs.unicode:
        pattern = [
            ".::..::..::..::..",
            "::##::##::##::##",
            "..::..::..::..::",
            ":##::##::##::##:",
        ]
    else:
        pattern = [
            "⣀⣄⣆⣶⣷⣶⣆⣄⣀⣄⣆⣶⣷⣶",
            "⠄⠒⠲⣄⣉⣩⣤⣴⣶⣶⣶⣤⣉⣁",
            "⡀⢀⣠⣶⣾⣿⣿⣿⣷⣶⣤⡀⠄⠄",
            "⢀⣴⣿⣿⡿⠛⠉⠉⠛⢿⣿⣿⣦⡀",
        ]
    rows: list[str] = []
    for idx in range(height):
        base = pattern[idx % len(pattern)]
        tiled = (base * ((width // len(base)) + 2))[:width]
        rows.append(tiled)
    return rows

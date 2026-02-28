from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfirmModal:
    title: str
    detail: str
    cancel_label: str = "Cancel"
    confirm_label: str = "Confirm"

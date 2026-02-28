from __future__ import annotations

import os
import select
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Callable

from .models import AppPaths

REMOTE_SCRIPT_BASE = "https://raw.githubusercontent.com/2high4schooltoday/new-mail-client/main/scripts"


class CancelToken:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


def detect_paths() -> AppPaths:
    # 1) In-repo layout: <root>/scripts/tui/system_ops.py
    script = Path(__file__).resolve()
    candidate_scripts = script.parents[1]
    candidate_root = candidate_scripts.parent
    if (candidate_scripts / "auto_install.sh").exists() and (candidate_root / "go.mod").exists():
        scripts_dir = candidate_scripts
        root_dir = candidate_root
        return AppPaths(
            root_dir=root_dir,
            scripts_dir=scripts_dir,
            install_script=scripts_dir / "auto_install.sh",
            uninstall_script=scripts_dir / "uninstall.sh",
            diagnose_script=scripts_dir / "diagnose_access.sh",
        )

    # 2) Current working directory includes checked-out repo.
    cwd = Path.cwd()
    if (cwd / "scripts" / "auto_install.sh").exists():
        return AppPaths(
            root_dir=cwd,
            scripts_dir=cwd / "scripts",
            install_script=cwd / "scripts" / "auto_install.sh",
            uninstall_script=cwd / "scripts" / "uninstall.sh",
            diagnose_script=cwd / "scripts" / "diagnose_access.sh",
        )

    # 3) Standalone mode: cache scripts from GitHub raw.
    cache_scripts = Path.home() / ".cache" / "mailclient-tui" / "scripts"
    cache_scripts.mkdir(parents=True, exist_ok=True)
    for filename in ("auto_install.sh", "uninstall.sh", "diagnose_access.sh"):
        target = cache_scripts / filename
        if not target.exists():
            urllib.request.urlretrieve(f"{REMOTE_SCRIPT_BASE}/{filename}", target)
            target.chmod(0o755)
    scripts_dir = cache_scripts
    root_dir = Path.cwd()
    return AppPaths(
        root_dir=root_dir,
        scripts_dir=scripts_dir,
        install_script=scripts_dir / "auto_install.sh",
        uninstall_script=scripts_dir / "uninstall.sh",
        diagnose_script=scripts_dir / "diagnose_access.sh",
    )


def have_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def detect_service_state() -> str:
    if not have_cmd("systemctl"):
        return "n/a"
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", "mailclient"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
        return (proc.stdout or proc.stderr).strip() or "unknown"
    except Exception:
        return "unknown"


def detect_arch() -> str:
    return os.uname().machine


def detect_host() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def detect_proxy_candidates() -> list[str]:
    out: list[str] = []
    if have_cmd("nginx"):
        out.append("nginx")
    if have_cmd("apache2ctl") or have_cmd("apache2"):
        out.append("apache2")
    return out


def stream_command(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    cancel: CancelToken,
    on_line: Callable[[str], None],
) -> int:
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )
    assert proc.stdout is not None

    fd = proc.stdout.fileno()
    while True:
        if cancel.cancelled and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break

        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            line = proc.stdout.readline()
            if line:
                on_line(line.rstrip("\n"))
        if proc.poll() is not None:
            # Drain trailing lines.
            for rem in proc.stdout.readlines():
                on_line(rem.rstrip("\n"))
            break

    return int(proc.returncode or 0)


def command_output(cmd: list[str], timeout: float = 2.0) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or proc.stderr).strip()
    except Exception:
        return ""


def now_ms() -> int:
    return int(time.time() * 1000)

"""Lightweight runtime diagnostics helpers for log correlation."""

from __future__ import annotations

import asyncio
import logging
import os
from distutils.util import strtobool
from pathlib import Path

PROCESS_STATUS_PATH = Path("/proc/self/status")
PROCESS_FD_PATH = Path("/proc/self/fd")


def runtime_diagnostics_enabled() -> bool:
    return bool(strtobool(os.getenv("LOG_RUNTIME_DIAGNOSTICS", "0")))


def _extract_status_kb_value(status_text: str, field_name: str) -> int | None:
    field_prefix = field_name + ":"
    for line in status_text.splitlines():
        if not line.startswith(field_prefix):
            continue
        field_parts = line.split()
        if len(field_parts) < 2:
            return None
        try:
            return int(field_parts[1])
        except ValueError:
            return None
    return None


def _extract_status_int_value(status_text: str, field_name: str) -> int | None:
    field_prefix = field_name + ":"
    for line in status_text.splitlines():
        if not line.startswith(field_prefix):
            continue
        field_parts = line.split()
        if len(field_parts) < 2:
            return None
        try:
            return int(field_parts[1])
        except ValueError:
            return None
    return None


def read_process_runtime_snapshot(status_text: str | None = None) -> dict[str, int | None]:
    if status_text is None:
        try:
            status_text = PROCESS_STATUS_PATH.read_text(encoding="utf-8")
        except OSError:
            status_text = ""

    open_fds: int | None = None
    try:
        open_fds = len(os.listdir(PROCESS_FD_PATH))
    except OSError:
        open_fds = None

    asyncio_tasks: int | None = None
    try:
        asyncio_tasks = len(asyncio.all_tasks())
    except RuntimeError:
        asyncio_tasks = None

    return {
        "rss_kb": _extract_status_kb_value(status_text, "VmRSS"),
        "swap_kb": _extract_status_kb_value(status_text, "VmSwap"),
        "vm_size_kb": _extract_status_kb_value(status_text, "VmSize"),
        "threads": _extract_status_int_value(status_text, "Threads"),
        "open_fds": open_fds,
        "asyncio_tasks": asyncio_tasks,
    }


def format_process_runtime_snapshot(
    snapshot: dict[str, int | None] | None = None,
) -> str:
    if snapshot is None:
        snapshot = read_process_runtime_snapshot()
    return (
        "rss_kb={rss_kb} swap_kb={swap_kb} vm_size_kb={vm_size_kb} "
        "threads={threads} open_fds={open_fds} asyncio_tasks={asyncio_tasks}"
    ).format(
        rss_kb=snapshot.get("rss_kb", "unknown"),
        swap_kb=snapshot.get("swap_kb", "unknown"),
        vm_size_kb=snapshot.get("vm_size_kb", "unknown"),
        threads=snapshot.get("threads", "unknown"),
        open_fds=snapshot.get("open_fds", "unknown"),
        asyncio_tasks=snapshot.get("asyncio_tasks", "unknown"),
    )


def log_with_runtime_snapshot(
    logger: logging.Logger,
    level: int,
    message: str,
    *args,
    **kwargs,
):
    if runtime_diagnostics_enabled():
        logger.log(
            level,
            message + " | %s",
            *args,
            format_process_runtime_snapshot(),
            **kwargs,
        )
        return
    logger.log(level, message, *args, **kwargs)

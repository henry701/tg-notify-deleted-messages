"""Shared simple configuration helpers for runtime behavior.

This module provides small, testable helpers to read environment-based
configuration and compute derived values that influence runtime behavior
without scattering logic across modules.
"""

from __future__ import annotations

import os
from typing import Optional


# Default values for chunk-size related configuration. Negative values mean
# "not configured" and should be ignored by call sites.
TELETHON_OVERRIDE_MAX_CHUNK_SIZE_DEFAULT = -1
TELEGRAM_MAX_CHUNK_SIZE_DEFAULT = -1


def get_env_int(name: str, default: int) -> int:
    """Safely read an int from an environment variable.

    If the value cannot be parsed as int, the provided default is returned.
    """
    val = os.environ.get(name, None)
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def validate_chunk_size(value: int, min_value: int, max_value: int) -> int:
    """Clamp a chunk size to a configured inclusive range."""
    if value < min_value:
        return min_value
    if value > max_value:
        return max_value
    return value


def compute_effective_chunk_size(
    override_env_val: int, telegram_max_env: Optional[str]
) -> int:
    """Compute the effective max chunk size to use.

    Priority:
      1) If TELEGRAM_MAX_CHUNK_SIZE is provided and parses to a positive int,
         that value overrides TELETHON_OVERRIDE_MAX_CHUNK_SIZE.
      2) Otherwise, use the TELETHON_OVERRIDE_MAX_CHUNK_SIZE value.
      3) If neither is positive, return the negative value to indicate "not set".
    """
    effective = int(override_env_val)
    if telegram_max_env:
        try:
            parsed = int(telegram_max_env)
            if parsed > 0:
                effective = parsed
        except ValueError:
            # ignore invalid values; fall back to override_env_val
            pass
    return effective

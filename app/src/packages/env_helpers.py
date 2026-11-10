import logging
import os
from pathlib import Path

from dotenv import load_dotenv

_TRUE_STRINGS = frozenset({"y", "yes", "t", "true", "on", "1"})
_FALSE_STRINGS = frozenset({"n", "no", "f", "false", "off", "0"})


def load_env(dot_env_folder):
    env_path = Path(dot_env_folder) / ".env"
    if os.path.isfile(env_path):
        load_dotenv(dotenv_path=env_path)


def require_env(name: str):
    got = os.getenv(name)
    if got is None:
        logging.critical(f"{name} environment variable is not set!")
        exit(1)
    return got


def parse_bool(value: str) -> bool:
    """Parse a boolean flag the way distutils.util.strtobool did (case-insensitive).

    Accepts y/yes/t/true/on/1 and n/no/f/false/off/0; surrounding whitespace is ignored.
    Raises ValueError for anything else.
    """
    normalized = value.strip().lower()
    if normalized in _TRUE_STRINGS:
        return True
    if normalized in _FALSE_STRINGS:
        return False
    raise ValueError(f"invalid truth value {value!r}")


def env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable; unset falls back to ``default``."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return parse_bool(raw)
    except ValueError as exc:
        raise ValueError(f"{name}: {exc}") from None

import os
import importlib


def test_get_env_int_reads_existing_value(monkeypatch):
    monkeypatch.setenv("SOME_INT", "42")
    from packages.config import get_env_int

    assert get_env_int("SOME_INT", 7) == 42


def test_get_env_int_defaults_on_missing_and_invalid(monkeypatch):
    # missing returns default
    from packages.config import get_env_int

    assert get_env_int("MISSING_ENV_XXX", 5) == 5
    # invalid value returns default
    monkeypatch.setenv("BAD_INT", "not-an-int")
    assert get_env_int("BAD_INT", 9) == 9


def test_compute_effective_chunk_size_pref_overrides(monkeypatch):
    from packages.config import compute_effective_chunk_size

    # telegram max set -> uses it when positive
    res = compute_effective_chunk_size(-1, "2048")
    assert res == 2048
    # override remains when telegram max is not positive/invalid
    res = compute_effective_chunk_size(1024, None)
    assert res == 1024


def test_validate_chunk_size_clamps(monkeypatch):
    from packages.config import validate_chunk_size

    assert validate_chunk_size(5, 10, 100) == 10
    assert validate_chunk_size(50, 10, 100) == 50
    assert validate_chunk_size(-1, 0, 10) == 0

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.env_helpers import env_bool, load_env, parse_bool, require_env


class EnvHelpersTests(unittest.TestCase):
    def test_load_env_loads_dotenv_file_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_file = Path(tmp_dir) / ".env"
            env_file.write_text("TGDEL_TEST_LOAD_ENV=loaded\n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("TGDEL_TEST_LOAD_ENV", None)
                load_env(tmp_dir)
                self.assertEqual(os.getenv("TGDEL_TEST_LOAD_ENV"), "loaded")

    def test_load_env_ignores_missing_dotenv_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("TGDEL_TEST_MISSING_ENV", None)
                load_env(tmp_dir)
                self.assertIsNone(os.getenv("TGDEL_TEST_MISSING_ENV"))

    def test_require_env_returns_existing_value(self) -> None:
        with patch.dict(os.environ, {"TGDEL_REQUIRED_VAR": "ok"}, clear=True):
            self.assertEqual(require_env("TGDEL_REQUIRED_VAR"), "ok")

    def test_require_env_exits_when_variable_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit) as raised:
                require_env("TGDEL_REQUIRED_VAR")
            self.assertEqual(raised.exception.code, 1)


class ParseBoolTests(unittest.TestCase):
    def test_accepts_strtobool_true_spellings(self) -> None:
        for raw in ("y", "YES", "t", "True", "on", "1", " true\n"):
            with self.subTest(raw=raw):
                self.assertIs(parse_bool(raw), True)

    def test_accepts_strtobool_false_spellings(self) -> None:
        for raw in ("n", "No", "f", "FALSE", "off", "0", " 0 "):
            with self.subTest(raw=raw):
                self.assertIs(parse_bool(raw), False)

    def test_rejects_unknown_values(self) -> None:
        for raw in ("", "2", "maybe", "truee", "-1"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_bool(raw)


class EnvBoolTests(unittest.TestCase):
    def test_unset_returns_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIs(env_bool("TGDEL_FLAG", True), True)
            self.assertIs(env_bool("TGDEL_FLAG", False), False)

    def test_set_value_overrides_default(self) -> None:
        with patch.dict(os.environ, {"TGDEL_FLAG": "off"}, clear=True):
            self.assertIs(env_bool("TGDEL_FLAG", True), False)
        with patch.dict(os.environ, {"TGDEL_FLAG": "Yes"}, clear=True):
            self.assertIs(env_bool("TGDEL_FLAG", False), True)

    def test_invalid_value_names_the_variable(self) -> None:
        with patch.dict(os.environ, {"TGDEL_FLAG": "sometimes"}, clear=True):
            with self.assertRaisesRegex(ValueError, "TGDEL_FLAG"):
                env_bool("TGDEL_FLAG", False)

    def test_empty_value_is_invalid_like_strtobool(self) -> None:
        with patch.dict(os.environ, {"TGDEL_FLAG": ""}, clear=True):
            with self.assertRaises(ValueError):
                env_bool("TGDEL_FLAG", True)

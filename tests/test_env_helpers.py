import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.env_helpers import load_env, require_env


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

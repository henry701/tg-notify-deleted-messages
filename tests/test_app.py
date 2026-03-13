import unittest
from unittest.mock import MagicMock, patch


class AppMainTests(unittest.TestCase):
    @patch("packages.env_helpers.require_env", return_value="5000")
    @patch("packages.bootstrap.create_app_and_start_jobs")
    def test_main_creates_app_and_runs(self, mock_create, mock_require_env):
        from app import main

        flask_app_mock = MagicMock()
        closer_mock = MagicMock()
        mock_create.return_value = (flask_app_mock, closer_mock)

        main()

        mock_create.assert_called_once()
        flask_app_mock.run.assert_called_once_with(port=5000, host="0.0.0.0")
        closer_mock.assert_called_once()


class AppImportsTests(unittest.TestCase):
    def test_import_main(self):
        from app import main

        self.assertTrue(callable(main))


if __name__ == "__main__":
    unittest.main()

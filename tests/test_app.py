#!/usr/bin/env python
import os

os.environ["DATABASE_URL"] = "sqlite:///test.db"

import unittest


class AppImportsTests(unittest.TestCase):
    def test_import_main(self):
        from app import main

        self.assertTrue(callable(main))


if __name__ == "__main__":
    unittest.main()

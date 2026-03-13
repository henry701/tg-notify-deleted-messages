import os
import unittest
from unittest.mock import patch

import sqlalchemy
from sqlalchemy.orm import sessionmaker

from packages.db_bootstrap import (
    create_engine,
    create_engine_from_env,
    create_session_factory,
)


class CreateEngineTests(unittest.TestCase):
    def test_creates_engine_with_database_url(self):
        engine = create_engine("sqlite:///:memory:")
        self.assertIsInstance(engine, sqlalchemy.engine.Engine)
        engine.dispose()

    def test_reuses_pool_when_provided(self):
        base_engine = create_engine("sqlite:///:memory:")
        pool = base_engine.pool
        reused_engine = create_engine("sqlite:///:memory:", pool=pool)
        self.assertIs(reused_engine.pool, pool)
        base_engine.dispose()
        reused_engine.dispose()

    @patch.dict(
        os.environ, {"CUSTOM_SQLALCHEMY_CONNECT_ARGS": '{"timeout": 30}'}, clear=False
    )
    def test_uses_custom_connect_args_from_env(self):
        engine = create_engine("sqlite:///:memory:")
        self.assertIsInstance(engine, sqlalchemy.engine.Engine)
        engine.dispose()

    @patch.dict(
        os.environ,
        {"CUSTOM_SQLALCHEMY_CREATE_ENGINE_ARGS": '{"echo": false}'},
        clear=False,
    )
    def test_uses_custom_create_engine_args_from_env(self):
        engine = create_engine("sqlite:///:memory:")
        self.assertIsInstance(engine, sqlalchemy.engine.Engine)
        engine.dispose()

    def test_ignores_missing_env_vars(self):
        env = {
            k: v for k, v in os.environ.items() if not k.startswith("CUSTOM_SQLALCHEMY")
        }
        with patch.dict(os.environ, env, clear=True):
            engine = create_engine("sqlite:///:memory:")
            self.assertIsInstance(engine, sqlalchemy.engine.Engine)
            engine.dispose()


class CreateEngineFromEnvTests(unittest.TestCase):
    @patch("packages.db_bootstrap.get_db_url")
    def test_calls_get_db_url_and_creates_engine(self, mock_get_db_url):
        mock_get_db_url.return_value = "sqlite:///:memory:"
        engine = create_engine_from_env()
        mock_get_db_url.assert_called_once()
        self.assertIsInstance(engine, sqlalchemy.engine.Engine)
        engine.dispose()


class CreateSessionFactoryTests(unittest.TestCase):
    def test_returns_sessionmaker_bound_to_engine(self):
        engine = create_engine("sqlite:///:memory:")
        factory = create_session_factory(engine)
        self.assertIsInstance(factory, sessionmaker)
        self.assertIs(factory.kw["bind"], engine)
        engine.dispose()

    def test_session_factory_has_expire_on_commit_false(self):
        engine = create_engine("sqlite:///:memory:")
        factory = create_session_factory(engine)
        self.assertFalse(factory.kw["expire_on_commit"])
        engine.dispose()

    def test_created_session_works(self):
        engine = create_engine("sqlite:///:memory:")
        factory = create_session_factory(engine)
        session = factory()
        self.assertIsNotNone(session)
        session.close()
        engine.dispose()


if __name__ == "__main__":
    unittest.main()

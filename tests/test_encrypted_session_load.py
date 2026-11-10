"""Regression tests for searchable AES ciphertext across Python versions.

``AesEngine.encrypt`` pickles values before AES. Python 3.14 changed
``pickle.DEFAULT_PROTOCOL`` from 4 (Python 3.12) to 5, so
``WHERE`` clauses on encrypted session columns missed existing rows and the
user Telethon session loaded unauthorized. Decrypt still worked
because ``pickle.loads`` reads older protocols.
"""

from __future__ import annotations

import base64
import pickle
import unittest

from alchemysession import AlchemySessionContainer
from packages.db_helpers import should_encrypt_column
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import declarative_base
from sqlalchemy_utils.types.encrypted.encrypted_type import (
    AesEngine,
    StringEncryptedType,
)
from telethon.crypto import AuthKey

TEST_ENCRYPTION_KEY = "unit-test-encryption-key"
LEGACY_SESSION_ID = "legacy_user"
LEGACY_AUTH_KEY = bytes((i % 256) for i in range(256))
LEGACY_DC_ID = 2
LEGACY_SERVER_ADDRESS = "149.154.167.51"
LEGACY_PORT = 443
# Protocol used by CPython 3.12 for pickle.dumps(value) with no
# protocol argument. Python 3.14's default is 5 and yields different bytes.
STABLE_PICKLE_PROTOCOL = 4


def _encrypt_with_pickle_protocol(
    typ: StringEncryptedType, value: object, protocol: int
) -> str:
    """Reproduce AesEngine.encrypt with an explicit pickle protocol."""
    typ._update_key()
    engine = typ.engine
    payload = engine.padding_engine.pad(pickle.dumps(value, protocol=protocol))
    encryptor = engine.cipher.encryptor()
    encrypted = encryptor.update(payload) + encryptor.finalize()
    return base64.b64encode(encrypted).decode("ascii")


def _build_encrypted_session_container():
    base = declarative_base()
    engine = create_engine("sqlite:///:memory:")
    container = AlchemySessionContainer(
        engine=engine,
        table_base=base,
        manage_tables=False,
        table_prefix="thon_",
    )
    container.core_mode = True
    for table in base.metadata.tables.values():
        for column in table.columns:
            if should_encrypt_column(column):
                column.type = StringEncryptedType(
                    column.type, TEST_ENCRYPTION_KEY, AesEngine, "pkcs5"
                )
    base.metadata.create_all(engine)
    return engine, container


class AesEnginePickleProtocolTests(unittest.TestCase):
    def test_encrypt_uses_pickle_protocol_4_not_python314_default(self) -> None:
        typ = StringEncryptedType(
            "unused", TEST_ENCRYPTION_KEY, AesEngine, "pkcs5"
        )
        typ._update_key()
        value = LEGACY_SESSION_ID
        actual = typ.engine.encrypt(value)
        proto4 = _encrypt_with_pickle_protocol(typ, value, 4)
        proto5 = _encrypt_with_pickle_protocol(typ, value, 5)
        self.assertNotEqual(
            proto4,
            proto5,
            "protocol 4 and 5 must differ so this regression stays meaningful",
        )
        self.assertEqual(
            actual,
            proto4,
            "searchable AES ciphertext must match Python 3.12 pickle protocol 4",
        )


class LegacyEncryptedSessionLoadTests(unittest.TestCase):
    def test_load_and_has_session_find_rows_written_with_pickle_protocol_4(
        self,
    ) -> None:
        engine, container = _build_encrypted_session_container()
        table = container.Session.__table__
        # Insert ciphertext the way Python 3.12 wrote it, bypassing
        # the current bind processor (which may still use protocol 5).
        params = {
            "session_id": _encrypt_with_pickle_protocol(
                table.c.session_id.type, LEGACY_SESSION_ID, STABLE_PICKLE_PROTOCOL
            ),
            "dc_id": _encrypt_with_pickle_protocol(
                table.c.dc_id.type, LEGACY_DC_ID, STABLE_PICKLE_PROTOCOL
            ),
            "server_address": _encrypt_with_pickle_protocol(
                table.c.server_address.type,
                LEGACY_SERVER_ADDRESS,
                STABLE_PICKLE_PROTOCOL,
            ),
            "port": LEGACY_PORT,
            "auth_key": _encrypt_with_pickle_protocol(
                table.c.auth_key.type, LEGACY_AUTH_KEY, STABLE_PICKLE_PROTOCOL
            ),
        }
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO thon_sessions "
                    "(session_id, dc_id, server_address, port, auth_key) "
                    "VALUES (:session_id, :dc_id, :server_address, :port, :auth_key)"
                ),
                params,
            )

        # The production bug: SELECT without WHERE can decrypt the row, but
        # WHERE session_id = :id uses a different pickle protocol and misses it.
        with engine.begin() as conn:
            unfiltered = conn.execute(select(table.c.session_id, table.c.auth_key)).all()
            filtered = conn.execute(
                select(table.c.session_id, table.c.auth_key).where(
                    table.c.session_id == LEGACY_SESSION_ID
                )
            ).all()
        self.assertEqual(len(unfiltered), 1)
        self.assertEqual(unfiltered[0][0], LEGACY_SESSION_ID)
        self.assertEqual(unfiltered[0][1], LEGACY_AUTH_KEY)
        self.assertEqual(
            len(filtered),
            1,
            "WHERE on encrypted session_id must match rows written under Python 3.12",
        )

        self.assertTrue(container.has_session(LEGACY_SESSION_ID))
        session = container.new_session(LEGACY_SESSION_ID)
        self.assertIsNotNone(session.auth_key)
        self.assertIsInstance(session.auth_key, AuthKey)
        self.assertEqual(session.auth_key.key, LEGACY_AUTH_KEY)
        self.assertEqual(session._dc_id, LEGACY_DC_ID)
        self.assertEqual(session.server_address, LEGACY_SERVER_ADDRESS)
        self.assertEqual(session.port, LEGACY_PORT)
        engine.dispose()

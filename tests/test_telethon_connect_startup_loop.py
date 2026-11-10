"""Regression: TelegramClient.connect via bootstrap's startup loop on 3.14.

Connecting with nest_asyncio applied crashed at bot/user connect with:

    RuntimeError: Timeout should be used inside a task

because nest_asyncio 1.6.0 was applied before loop.run_until_complete, and
Python 3.14's asyncio.wait_for uses timeouts.timeout(), which requires a
real current Task. nest_asyncio is archived (no 3.14 fix). This test uses
a real TelegramClient against a local dummy TCP server (no Telegram network)
and the same loop.run_until_complete startup path as create_app_and_start_jobs.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import unittest

from telethon import TelegramClient
from telethon.sessions import MemorySession

# Dummy values only; this test never reaches Telegram auth.
_DUMMY_API_ID = 1
_DUMMY_API_HASH = "0123456789abcdef0123456789abcdef"


def _start_dummy_tcp_server() -> tuple[threading.Event, int]:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]
    stop = threading.Event()

    def accept_loop() -> None:
        server.settimeout(0.5)
        while not stop.is_set():
            try:
                client, _ = server.accept()
                try:
                    client.recv(16)
                finally:
                    client.close()
            except socket.timeout:
                continue
            except OSError:
                break
        try:
            server.close()
        except OSError:
            pass

    threading.Thread(target=accept_loop, daemon=True).start()
    return stop, port


class ContainerPythonVersionTests(unittest.TestCase):
    def test_ci_image_is_python_3_14(self):
        self.assertEqual(
            sys.version_info[:2],
            (3, 14),
            f"Dockerfile pins CPython 3.14 on Alpine 3.24; got {sys.version}",
        )


class TelegramConnectStartupLoopTests(unittest.TestCase):
    def test_connect_via_run_until_complete_does_not_raise_timeout_task_error(self):
        stop, port = _start_dummy_tcp_server()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def connect() -> None:
            session = MemorySession()
            session.set_dc(1, "127.0.0.1", port)
            client = TelegramClient(
                session,
                _DUMMY_API_ID,
                _DUMMY_API_HASH,
                loop=loop,
                connection_retries=0,
                retry_delay=0,
                timeout=2,
            )
            await client.connect()

        try:
            loop.run_until_complete(connect())
        except Exception as exc:
            # Dummy server is not MTProto; a transport/handshake error means
            # asyncio.wait_for / open_connection already ran successfully.
            if isinstance(exc, RuntimeError) and "Timeout should be used inside a task" in str(exc):
                self.fail(
                    "TelegramClient.connect via loop.run_until_complete raised "
                    "the Python 3.14 nest_asyncio timeout error: "
                    f"{exc!r}"
                )
        finally:
            stop.set()
            loop.close()

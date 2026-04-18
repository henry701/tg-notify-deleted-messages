import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from packages.http import add_informative_routes
from packages.models.support.PeerType import PeerType


def close_coro_and_return(coro, future):
    coro.close()
    return future


class AddInformativeRoutesTests(unittest.TestCase):
    def setUp(self):
        from flask import Flask

        self.app = Flask(__name__)
        self.client_mock = MagicMock()
        self.bot_mock = MagicMock()
        self.loop_mock = MagicMock()
        self.session_maker_mock = MagicMock()

    def test_is_bot_connected_route(self):
        self.bot_mock.client = MagicMock()
        self.bot_mock.client.is_connected.return_value = True
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/is_bot_connected")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "True")

    def test_is_bot_connected_no_bot(self):
        add_informative_routes(
            self.client_mock,
            None,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/is_bot_connected")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "False")

    def test_is_connected_route(self):
        self.client_mock.is_connected.return_value = True
        add_informative_routes(
            self.client_mock,
            None,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/is_connected")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "True")

    def test_save_sessions_route(self):
        self.client_mock.session = MagicMock()
        add_informative_routes(
            self.client_mock,
            None,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/save_sessions")
            self.assertEqual(response.status_code, 204)
            self.client_mock.session.save.assert_called_once()

    def test_save_sessions_with_bot(self):
        self.client_mock.session = MagicMock()
        self.bot_mock.client = MagicMock()
        self.bot_mock.client.session = MagicMock()
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/save_sessions")
            self.assertEqual(response.status_code, 204)
            self.client_mock.session.save.assert_called_once()
            self.bot_mock.client.session.save.assert_called_once()


class PreloadCheckpointRouteTests(unittest.TestCase):
    def setUp(self):
        from flask import Flask

        self.app = Flask(__name__)
        self.client_mock = MagicMock()
        self.bot_mock = MagicMock()
        self.loop_mock = MagicMock()
        self.session_maker_mock = MagicMock()
        self.sample_timestamp = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)

    def _build_checkpoint(self):
        checkpoint = MagicMock()
        checkpoint.chat_peer_id = 321
        checkpoint.preloaded_through_message_id = 99
        checkpoint.preloaded_through_timestamp = self.sample_timestamp
        checkpoint.updated_at = self.sample_timestamp
        checkpoint.chat_peer = MagicMock()
        checkpoint.chat_peer.peer_id = 123456
        checkpoint.chat_peer.type = PeerType.CHANNEL
        return checkpoint

    @patch("packages.http.list_preload_checkpoints")
    def test_get_preload_checkpoints_route(self, list_checkpoints_mock):
        list_checkpoints_mock.return_value = [self._build_checkpoint()]
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )

        with self.app.test_client() as client:
            response = client.get("/preload_checkpoints")
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(len(payload["checkpoints"]), 1)
            self.assertEqual(payload["checkpoints"][0]["chat_peer_id"], 321)
            self.assertEqual(payload["checkpoints"][0]["peer_id"], 123456)
            self.assertEqual(
                payload["checkpoints"][0]["peer_type"], int(PeerType.CHANNEL)
            )
            self.assertEqual(
                payload["checkpoints"][0]["peer_type_name"], PeerType.CHANNEL.name
            )
            self.assertEqual(
                payload["checkpoints"][0]["preloaded_through_message_id"], 99
            )

    @patch("packages.http.upsert_preload_checkpoint")
    @patch("packages.http.find_chat_peer_id_for_checkpoint_query")
    def test_set_preload_checkpoint_route_with_peer_lookup(
        self, find_chat_peer_id_mock, upsert_checkpoint_mock
    ):
        checkpoint = self._build_checkpoint()
        find_chat_peer_id_mock.return_value = 321
        upsert_checkpoint_mock.return_value = checkpoint
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )

        with self.app.test_client() as client:
            response = client.post(
                "/preload_checkpoints/set"
                "?peer_id=123456&peer_type=CHANNEL&timestamp=2026-04-08T12:00:00Z&message_id=99"
            )
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload["checkpoint"]["chat_peer_id"], 321)

        find_chat_peer_id_mock.assert_called_once_with(
            sqlalchemy_session_maker=self.session_maker_mock,
            peer_id=123456,
            peer_type=PeerType.CHANNEL,
        )
        upsert_checkpoint_mock.assert_called_once_with(
            chat_peer_id=321,
            preloaded_through_timestamp=self.sample_timestamp,
            preloaded_through_message_id=99,
            sqlalchemy_session_maker=self.session_maker_mock,
        )

    @patch("packages.http.find_chat_peer_id_for_checkpoint_query")
    def test_set_preload_checkpoint_returns_404_for_unknown_direct_chat_peer_id(
        self, find_chat_peer_id_mock
    ):
        find_chat_peer_id_mock.return_value = None
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )

        with self.app.test_client() as client:
            response = client.post(
                "/preload_checkpoints/set"
                "?chat_peer_id=321&timestamp=2026-04-08T12:00:00Z"
            )
            self.assertEqual(response.status_code, 404)

        find_chat_peer_id_mock.assert_called_once_with(
            sqlalchemy_session_maker=self.session_maker_mock,
            chat_peer_id=321,
        )

    def test_set_preload_checkpoint_rejects_naive_timestamp(self):
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )

        with self.app.test_client() as client:
            response = client.post(
                "/preload_checkpoints/set"
                "?chat_peer_id=321&timestamp=2026-04-08T12:00:00"
            )
            self.assertEqual(response.status_code, 400)

    @patch("packages.http.clear_all_preload_checkpoints")
    def test_clear_all_preload_checkpoints_route(self, clear_all_mock):
        clear_all_mock.return_value = 4
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )

        with self.app.test_client() as client:
            response = client.post("/preload_checkpoints/clear")
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload["deleted"], 4)

    @patch("packages.http.find_chat_peer_id_for_checkpoint_query")
    @patch("packages.http.clear_preload_checkpoint")
    def test_clear_single_preload_checkpoint_route(
        self, clear_checkpoint_mock, find_chat_peer_id_mock
    ):
        clear_checkpoint_mock.return_value = 1
        find_chat_peer_id_mock.return_value = 321
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )

        with self.app.test_client() as client:
            response = client.post("/preload_checkpoints/clear?chat_peer_id=321")
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload["chat_peer_id"], 321)
            self.assertEqual(payload["deleted"], 1)

        find_chat_peer_id_mock.assert_called_once_with(
            sqlalchemy_session_maker=self.session_maker_mock,
            chat_peer_id=321,
        )
        clear_checkpoint_mock.assert_called_once_with(321, self.session_maker_mock)

    @patch("packages.http.find_chat_peer_id_for_checkpoint_query")
    def test_clear_single_preload_checkpoint_returns_404_for_unknown_chat_peer_id(
        self, find_chat_peer_id_mock
    ):
        find_chat_peer_id_mock.return_value = None
        add_informative_routes(
            self.client_mock,
            self.bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )

        with self.app.test_client() as client:
            response = client.post("/preload_checkpoints/clear?chat_peer_id=321")
            self.assertEqual(response.status_code, 404)

        find_chat_peer_id_mock.assert_called_once_with(
            sqlalchemy_session_maker=self.session_maker_mock,
            chat_peer_id=321,
        )


class CreateAppTests(unittest.TestCase):
    def test_raises_on_none_client(self):
        from packages.http import create_app

        with self.assertRaises(ValueError):
            create_app(None, None, MagicMock(), MagicMock(), MagicMock())

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    def test_creates_flask_app(self):
        from packages.http import create_app

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        self.assertIsNotNone(flask_app)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456", "HTTP_BEARER_TOKEN": "secret"})
    def test_bearer_auth_rejects_invalid(self):
        from packages.http import create_app

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 401)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456", "HTTP_BEARER_TOKEN": "secret"})
    def test_bearer_auth_accepts_valid(self):
        from packages.http import create_app

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health", headers={"Authorization": "Bearer secret"})
            self.assertNotEqual(response.status_code, 401)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    def test_no_bearer_token_allows_all(self):
        from packages.http import create_app

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertNotEqual(response.status_code, 401)


class SendCodeRouteTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_send_code_returns_204(self, mock_run_coro):
        from packages.http import create_app

        future_mock = MagicMock()
        future_mock.result.return_value = MagicMock()
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/send_code")
            self.assertEqual(response.status_code, 204)


class LogoutRouteTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_logout_returns_204(self, mock_run_coro):
        from packages.http import create_app

        future_mock = MagicMock()
        future_mock.result.return_value = None
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/logout")
            self.assertEqual(response.status_code, 204)
            loop_mock.call_later.assert_called_once()


class AuthRouteTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    def test_auth_without_send_code_returns_401(self):
        from packages.http import create_app

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/auth?code=12345")
            self.assertEqual(response.status_code, 401)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_auth_without_code_or_password_returns_403(self, mock_run_coro):
        from packages.http import create_app

        future_mock = MagicMock()
        sent_code_mock = MagicMock()
        sent_code_mock.phone_code_hash = "test_hash"
        future_mock.result.return_value = sent_code_mock
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            client.get("/send_code")
            response = client.get("/auth")
            self.assertEqual(response.status_code, 403)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_auth_with_both_code_and_password_returns_400(self, mock_run_coro):
        from packages.http import create_app

        future_mock = MagicMock()
        sent_code_mock = MagicMock()
        sent_code_mock.phone_code_hash = "test_hash"
        future_mock.result.return_value = sent_code_mock
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            client.get("/send_code")
            response = client.get("/auth?code=123&password=pass")
            self.assertEqual(response.status_code, 400)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_auth_success_returns_204(self, mock_run_coro):
        import telethon.types
        from packages.http import create_app

        send_future = MagicMock()
        send_future.result.return_value = MagicMock()

        user_mock = MagicMock(spec=telethon.types.User)
        sign_in_future = MagicMock()
        sign_in_future.result.return_value = user_mock

        preload_future = MagicMock()
        preload_future.add_done_callback = MagicMock()

        def run_coro_side_effect(coro, loop):
            coro_str = str(coro)
            coro.close()
            if "send_code" in coro_str:
                return send_future
            elif "sign_in" in coro_str:
                return sign_in_future
            elif "preload" in coro_str:
                return preload_future
            return MagicMock()

        mock_run_coro.side_effect = run_coro_side_effect

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            client.get("/send_code")
            response = client.get("/auth?code=12345")
            self.assertEqual(response.status_code, 204)


class IsBotAuthorizedRouteTests(unittest.TestCase):
    def setUp(self):
        from flask import Flask

        self.app = Flask(__name__)
        self.client_mock = MagicMock()
        self.loop_mock = MagicMock()
        self.session_maker_mock = MagicMock()

    @patch("asyncio.run_coroutine_threadsafe")
    def test_is_bot_authorized_with_bot(self, mock_run_coro):
        bot_mock = MagicMock()
        bot_mock.client = MagicMock()

        future_mock = MagicMock()
        future_mock.result.return_value = True
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        add_informative_routes(
            self.client_mock,
            bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/is_bot_authorized")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "True")

    def test_is_bot_authorized_without_bot(self):
        add_informative_routes(
            self.client_mock,
            None,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/is_bot_authorized")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "False")


class IsAuthorizedRouteTests(unittest.TestCase):
    @patch("asyncio.run_coroutine_threadsafe")
    def test_is_authorized_returns_true(self, mock_run_coro):
        from flask import Flask

        app = Flask(__name__)
        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()

        future_mock = MagicMock()
        future_mock.result.return_value = True
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        add_informative_routes(
            client_mock,
            None,
            app,
            loop_mock,
            session_maker_mock,
        )
        with app.test_client() as client:
            response = client.get("/is_authorized")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "True")


class HealthRouteTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_health_passes_when_all_ok(self, mock_run_coro):
        from packages.http import create_app

        future_mock = MagicMock()
        future_mock.result.return_value = True
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        client_mock = MagicMock()
        client_mock.is_connected.return_value = True
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        session_maker_mock = MagicMock()
        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 204)
        health_query = session_mock.execute.call_args.args[0]
        self.assertNotIn("telegram_messages", str(health_query))

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    def test_health_fails_when_loop_not_running(self):
        from packages.http import create_app

        client_mock = MagicMock()
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = False
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 500)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    def test_health_fails_when_client_not_connected(self):
        from packages.http import create_app

        client_mock = MagicMock()
        client_mock.is_connected.return_value = False
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 500)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    def test_health_fails_when_bot_not_connected(self):
        from packages.http import create_app

        client_mock = MagicMock()
        client_mock.is_connected.return_value = True
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        bot_mock = MagicMock()
        bot_mock.client = MagicMock()
        bot_mock.client.is_connected.return_value = False

        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, bot_mock, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 500)


class AuthRouteErrorTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_auth_key_unregistered_returns_401(self, mock_run_coro):
        import telethon.errors.rpcerrorlist
        from packages.http import create_app

        send_future = MagicMock()
        send_future.result.return_value = MagicMock()

        sign_in_future = MagicMock()
        sign_in_future.result.side_effect = (
            telethon.errors.rpcerrorlist.AuthKeyUnregisteredError(request=None)
        )

        def run_coro_side_effect(coro, loop):
            coro_str = str(coro)
            coro.close()
            if "send_code" in coro_str:
                return send_future
            elif "sign_in" in coro_str:
                return sign_in_future
            return MagicMock()

        mock_run_coro.side_effect = run_coro_side_effect

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            client.get("/send_code")
            response = client.get("/auth?code=12345")
            self.assertEqual(response.status_code, 401)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_session_password_needed_returns_401(self, mock_run_coro):
        from telethon.errors import SessionPasswordNeededError
        from packages.http import create_app

        send_future = MagicMock()
        send_future.result.return_value = MagicMock()

        sign_in_future = MagicMock()
        sign_in_future.result.side_effect = SessionPasswordNeededError(request=None)

        def run_coro_side_effect(coro, loop):
            coro_str = str(coro)
            coro.close()
            if "send_code" in coro_str:
                return send_future
            elif "sign_in" in coro_str:
                return sign_in_future
            return MagicMock()

        mock_run_coro.side_effect = run_coro_side_effect

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            client.get("/send_code")
            response = client.get("/auth?code=12345")
            self.assertEqual(response.status_code, 401)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_auth_unknown_signin_result_returns_500(self, mock_run_coro):
        from packages.http import create_app

        send_future = MagicMock()
        send_future.result.return_value = MagicMock()

        sign_in_future = MagicMock()
        sign_in_future.result.return_value = "unknown_result"

        def run_coro_side_effect(coro, loop):
            coro_str = str(coro)
            coro.close()
            if "send_code" in coro_str:
                return send_future
            elif "sign_in" in coro_str:
                return sign_in_future
            return MagicMock()

        mock_run_coro.side_effect = run_coro_side_effect

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            client.get("/send_code")
            response = client.get("/auth?code=12345")
            self.assertEqual(response.status_code, 500)


class HealthRouteDbErrorTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_health_fails_when_db_query_fails(self, mock_run_coro):
        from packages.http import create_app

        future_mock = MagicMock()
        future_mock.result.return_value = True
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        client_mock = MagicMock()
        client_mock.is_connected.return_value = True
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        session_maker_mock = MagicMock()
        session_mock = MagicMock()
        session_mock.execute.side_effect = Exception("DB connection lost")
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 500)


class SaveSessionsWithBotRouteTests(unittest.TestCase):
    def setUp(self):
        from flask import Flask

        self.app = Flask(__name__)
        self.client_mock = MagicMock()
        self.loop_mock = MagicMock()
        self.session_maker_mock = MagicMock()

    def test_save_sessions_with_bot(self):
        self.client_mock.session = MagicMock()
        bot_mock = MagicMock()
        bot_mock.client = MagicMock()
        bot_mock.client.session = MagicMock()
        add_informative_routes(
            self.client_mock,
            bot_mock,
            self.app,
            self.loop_mock,
            self.session_maker_mock,
        )
        with self.app.test_client() as client:
            response = client.get("/save_sessions")
            self.assertEqual(response.status_code, 204)
            self.client_mock.session.save.assert_called_once()
            bot_mock.client.session.save.assert_called_once()


class AuthRouteSentCodeTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_auth_sent_code_returns_401(self, mock_run_coro):
        from telethon.tl.types.auth import SentCode
        from packages.http import create_app

        send_future = MagicMock()
        send_future.result.return_value = MagicMock()

        sent_code_result = MagicMock(spec=SentCode)
        sent_code_result.phone_code_hash = "hash2"
        sign_in_future = MagicMock()
        sign_in_future.result.return_value = sent_code_result

        def run_coro_side_effect(coro, loop):
            coro_str = str(coro)
            coro.close()
            if "send_code" in coro_str:
                return send_future
            elif "sign_in" in coro_str:
                return sign_in_future
            return MagicMock()

        mock_run_coro.side_effect = run_coro_side_effect

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            client.get("/send_code")
            response = client.get("/auth?code=12345")
            self.assertEqual(response.status_code, 401)
            self.assertIn(b"auth is still incomplete", response.data)


class HealthRouteBotErrorTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_health_bot_error_is_returned_from_actual_health(self, mock_run_coro):
        from packages.http import create_app

        client_mock = MagicMock()
        client_mock.is_connected.return_value = True
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        bot_mock = MagicMock()
        bot_mock.client = MagicMock()
        bot_mock.client.is_connected.return_value = True

        session_maker_mock = MagicMock()
        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        auth_results = [True, Exception("Bot auth failed")]

        def run_coro_side_effect(coro, loop):
            outcome = auth_results.pop(0)
            future = MagicMock()
            if isinstance(outcome, Exception):
                future.result.side_effect = outcome
            else:
                future.result.return_value = outcome
            return close_coro_and_return(coro, future)

        mock_run_coro.side_effect = run_coro_side_effect

        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, bot_mock, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 500)
        self.assertEqual(mock_run_coro.call_count, 2)

    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_health_client_error_is_returned_from_actual_health(self, mock_run_coro):
        from packages.http import create_app

        client_mock = MagicMock()
        client_mock.is_connected.return_value = True
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        session_maker_mock = MagicMock()
        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        future = MagicMock()
        future.result.side_effect = Exception("Client auth failed")
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future
        )

        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )
        with flask_app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 500)
        self.assertEqual(mock_run_coro.call_count, 1)


class HealthConsecutiveFailuresTests(unittest.TestCase):
    @patch.dict(
        "os.environ",
        {"PHONE_NUMBER": "123456", "SUICIDE_AFTER_CONSECUTIVE_HEALTH_FAILURES": "0"},
    )
    @patch("asyncio.run_coroutine_threadsafe")
    def test_health_tracks_consecutive_failures_non_2xx(self, mock_run_coro):
        from packages.http import create_app

        client_mock = MagicMock()
        client_mock.is_connected.return_value = False
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        session_maker_mock = MagicMock()

        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )

        with flask_app.test_client() as client:
            client.get("/health")

        with flask_app.test_client() as client:
            client.get("/health")

    @patch.dict(
        "os.environ",
        {"PHONE_NUMBER": "123456", "SUICIDE_AFTER_CONSECUTIVE_HEALTH_FAILURES": "0"},
    )
    @patch("asyncio.run_coroutine_threadsafe")
    def test_health_resets_failures_on_success(self, mock_run_coro):
        from packages.http import create_app

        future_mock = MagicMock()
        future_mock.result.return_value = True
        mock_run_coro.side_effect = lambda coro, loop: close_coro_and_return(
            coro, future_mock
        )

        client_mock = MagicMock()
        client_mock.is_connected.return_value = True
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        session_maker_mock = MagicMock()
        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )

        with flask_app.test_client() as client:
            client.get("/health")

        client_mock.is_connected.return_value = False
        with flask_app.test_client() as client:
            client.get("/health")

    @patch.dict(
        "os.environ",
        {"PHONE_NUMBER": "123456", "SUICIDE_AFTER_CONSECUTIVE_HEALTH_FAILURES": "2"},
    )
    @patch("asyncio.run_coroutine_threadsafe")
    def test_health_suicide_on_consecutive_failures(self, mock_run_coro):
        from packages.http import create_app

        client_mock = MagicMock()
        client_mock.is_connected.return_value = False
        loop_mock = MagicMock()
        loop_mock.is_running.return_value = True

        session_maker_mock = MagicMock()

        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )

        with patch("packages.http.os._exit") as mock_exit:
            with flask_app.test_client() as client:
                client.get("/health")
            mock_exit.assert_not_called()

            with flask_app.test_client() as client:
                client.get("/health")
            mock_exit.assert_called_once_with(1)


class PreloadCallbackExceptionTests(unittest.TestCase):
    @patch.dict("os.environ", {"PHONE_NUMBER": "123456"})
    @patch("asyncio.run_coroutine_threadsafe")
    def test_preload_callback_exception_handled(self, mock_run_coro):
        import telethon.types
        from packages.http import create_app

        send_future = MagicMock()
        send_future.result.return_value = MagicMock()

        user_mock = MagicMock(spec=telethon.types.User)
        sign_in_future = MagicMock()
        sign_in_future.result.return_value = user_mock

        preload_future = MagicMock()

        def run_coro_side_effect(coro, loop):
            coro_str = str(coro)
            coro.close()
            if "send_code" in coro_str:
                return send_future
            elif "sign_in" in coro_str:
                return sign_in_future
            elif "preload" in coro_str:
                return preload_future
            return MagicMock()

        mock_run_coro.side_effect = run_coro_side_effect

        client_mock = MagicMock()
        loop_mock = MagicMock()
        session_maker_mock = MagicMock()
        sync_closer = MagicMock()
        flask_app = create_app(
            client_mock, None, loop_mock, session_maker_mock, sync_closer
        )

        with flask_app.test_client() as client:
            client.get("/send_code")

        def raise_in_callback(inner_future):
            inner_future.result.side_effect = Exception("preload failed")

        preload_future.add_done_callback.side_effect = raise_in_callback

        with flask_app.test_client() as client:
            response = client.get("/auth?code=12345")
            self.assertEqual(response.status_code, 204)


if __name__ == "__main__":
    unittest.main()

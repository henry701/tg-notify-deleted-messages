"""HTTP/Flask application setup and route definitions."""

import asyncio
import concurrent
import logging
import os
from datetime import datetime, timezone

import flask
import sqlalchemy
import telethon
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import select
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from tenacity import retry, retry_if_exception_type, stop_after_attempt

from packages.background_jobs import preload_messages
from packages.bot_assistant import BotAssistant
from packages.env_helpers import require_env
from packages.models.support.PeerType import PeerType
from packages.preload_checkpoints import (
    clear_all_preload_checkpoints,
    clear_preload_checkpoint,
    find_chat_peer_id_for_checkpoint_query,
    list_preload_checkpoints,
    upsert_preload_checkpoint,
)
from packages.runtime_diagnostics import format_process_runtime_snapshot

logger = logging.getLogger("tgdel-http")


def parse_iso8601_timestamp(value: str) -> datetime:
    normalized_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized_value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return parsed.astimezone(timezone.utc)


def parse_peer_type_query_value(value: str) -> PeerType:
    try:
        return PeerType(int(value))
    except (KeyError, TypeError, ValueError):
        pass
    try:
        return PeerType[value.strip().upper()]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid peer_type: {value}") from exc


def serialize_preload_checkpoint(checkpoint) -> dict:
    peer_type_value = (
        int(checkpoint.chat_peer.type)
        if checkpoint.chat_peer is not None and checkpoint.chat_peer.type is not None
        else None
    )
    peer_type_name = None
    if peer_type_value is not None:
        try:
            peer_type_name = PeerType(peer_type_value).name
        except ValueError:
            peer_type_name = None
    return {
        "chat_peer_id": int(checkpoint.chat_peer_id),
        "peer_id": (
            int(str(checkpoint.chat_peer.peer_id))
            if checkpoint.chat_peer is not None
            and checkpoint.chat_peer.peer_id is not None
            else None
        ),
        "peer_type": peer_type_value,
        "peer_type_name": peer_type_name,
        "preloaded_through_message_id": (
            int(str(checkpoint.preloaded_through_message_id))
            if checkpoint.preloaded_through_message_id is not None
            else None
        ),
        "preloaded_through_timestamp": checkpoint.preloaded_through_timestamp.isoformat(),
        "updated_at": checkpoint.updated_at.isoformat(),
    }


def create_app(
    client: TelegramClient | None,
    bot: BotAssistant | None,
    loop: asyncio.AbstractEventLoop,
    sqlalchemy_session_maker: sessionmaker,
    sync_closer,
) -> flask.Flask:
    if client is None:
        raise ValueError("Client not initialized!")

    flask_app = flask.Flask(__name__)

    phone = require_env("PHONE_NUMBER")

    sent_code: list = [None]

    add_informative_routes(client, bot, flask_app, loop, sqlalchemy_session_maker)

    bearer_token = os.getenv("HTTP_BEARER_TOKEN")

    @flask_app.before_request
    def before_request():
        if bearer_token is None:
            return
        auth_header_value = flask.request.headers.get("Authorization")
        if auth_header_value != f"Bearer {bearer_token}":
            return flask.Response(status=401)

    @flask_app.route("/send_code", methods=["GET"])
    def send_code():
        logger.info("Sending code request")
        sent_code[0] = asyncio.run_coroutine_threadsafe(
            client.send_code_request(phone=phone), loop
        ).result()
        logger.info("Sent code request")
        return flask.Response(status=204)

    @flask_app.route("/logout", methods=["GET"])
    def logout():
        logger.info("Logging out")
        asyncio.run_coroutine_threadsafe(client.log_out(), loop).result()
        logger.info("Logged out! Exiting, because client is unusable.")
        loop.call_later(1, sync_closer)
        return flask.Response(status=204)

    @flask_app.route("/auth", methods=["GET"])
    def auth():
        logger.info("Auth request received")
        code = flask.request.args.get("code")
        password = flask.request.args.get("password")
        if not sent_code[0]:
            return flask.Response("Missing send_code request", status=401)
        if not code and not password:
            return flask.Response(
                "Missing code and password queryParameter. Either one or the other should be present!",
                status=403,
            )
        if code and password:
            return flask.Response(
                "Both code and password parameters present, but either one or the other should be present!",
                status=400,
            )
        try:
            logger.info("Attempting to sign in")
            sign_in_result = asyncio.run_coroutine_threadsafe(
                client.sign_in(
                    phone_code_hash=sent_code[0].phone_code_hash,
                    phone=phone,
                    code=code,  # type: ignore
                    password=password,  # type: ignore
                ),
                loop,
            ).result()
            if isinstance(sign_in_result, telethon.types.User):
                preload_future = asyncio.run_coroutine_threadsafe(
                    preload_messages(client, sqlalchemy_session_maker), loop
                )

                def handle_preload_result(
                    preload_inner_future: concurrent.futures.Future,
                ):
                    try:
                        preload_inner_future.result()
                    except Exception as e:
                        logger.error(
                            f"Error while preloading after login: {e}",
                            exc_info=True,
                        )

                try:
                    preload_future.add_done_callback(handle_preload_result)
                except Exception as e:
                    logger.error(
                        f"Error while registering preload callback: {e}",
                        exc_info=True,
                    )
                return flask.Response(status=204)
            if isinstance(sign_in_result, telethon.types.auth.SentCode):
                sent_code[0] = sign_in_result
                return flask.Response(
                    "Sent code, but auth is still incomplete!", status=401
                )
            return flask.Response(
                "Unknown return from client.sign_in, probable Telethon or application bug!",
                status=500,
            )
        except (
            telethon.errors.rpcerrorlist.AuthKeyUnregisteredError,
            telethon.errors.rpcerrorlist.AuthKeyDuplicatedError,
        ):
            return flask.Response(
                "Missing new send_code request. Unregistered or duplicate!", status=401
            )
        except SessionPasswordNeededError:
            return flask.Response("Password needed!", status=401)

    return flask_app


def add_informative_routes(
    client: TelegramClient,
    bot: BotAssistant | None,
    flask_app: flask.Flask,
    loop: asyncio.AbstractEventLoop,
    sqlalchemy_session_maker: sessionmaker,
):
    @flask_app.route("/is_bot_connected", methods=["GET"])
    def is_bot_connected():
        return flask.Response(
            str(
                bot is not None and bot.client is not None and bot.client.is_connected()
            ),
            status=200,
        )

    @flask_app.route("/is_connected", methods=["GET"])
    def is_connected():
        return flask.Response(str(client.is_connected()), status=200)

    @flask_app.route("/is_bot_authorized", methods=["GET"])
    def is_bot_authorized():
        return flask.Response(
            str(
                bot is not None
                and bot.client is not None
                and asyncio.run_coroutine_threadsafe(
                    bot.client.is_user_authorized(), loop
                ).result()
            ),
            status=200,
        )

    @flask_app.route("/is_authorized", methods=["GET"])
    def is_authorized():
        return flask.Response(
            str(
                asyncio.run_coroutine_threadsafe(
                    client.is_user_authorized(), loop
                ).result()
            ),
            status=200,
        )

    @flask_app.route("/save_sessions", methods=["GET"])
    def save_sessions():
        client.session.save()
        if bot is not None and bot.client is not None:
            bot.client.session.save()
        return flask.Response(status=204)

    def resolve_checkpoint_chat_peer_id(require_target: bool) -> int | None:
        chat_peer_id_value = flask.request.args.get("chat_peer_id")
        if chat_peer_id_value is not None:
            resolved_chat_peer_id = find_chat_peer_id_for_checkpoint_query(
                sqlalchemy_session_maker=sqlalchemy_session_maker,
                chat_peer_id=int(chat_peer_id_value),
            )
            if resolved_chat_peer_id is None:
                raise LookupError("Unable to resolve peer to a known chat_peer_id.")
            return resolved_chat_peer_id

        peer_id_value = flask.request.args.get("peer_id")
        peer_type_value = flask.request.args.get("peer_type")
        if peer_id_value is None and peer_type_value is None:
            if require_target:
                raise ValueError(
                    "Missing target chat. Provide chat_peer_id or peer_id with peer_type."
                )
            return None
        if peer_id_value is None or peer_type_value is None:
            raise ValueError("peer_id and peer_type must be provided together.")

        resolved_chat_peer_id = find_chat_peer_id_for_checkpoint_query(
            sqlalchemy_session_maker=sqlalchemy_session_maker,
            peer_id=int(peer_id_value),
            peer_type=parse_peer_type_query_value(peer_type_value),
        )
        if resolved_chat_peer_id is None:
            raise LookupError("Unable to resolve peer to a known chat_peer_id.")
        return resolved_chat_peer_id

    @flask_app.route("/preload_checkpoints", methods=["GET"])
    def get_preload_checkpoints():
        checkpoints = list_preload_checkpoints(sqlalchemy_session_maker)
        return flask.jsonify(
            {"checkpoints": [serialize_preload_checkpoint(cp) for cp in checkpoints]}
        )

    @flask_app.route("/preload_checkpoints/set", methods=["POST"])
    def set_preload_checkpoint():
        try:
            chat_peer_id = resolve_checkpoint_chat_peer_id(require_target=True)
            timestamp_value = flask.request.args.get("timestamp")
            if timestamp_value is None:
                return flask.Response("Missing timestamp query parameter.", status=400)
            checkpoint = upsert_preload_checkpoint(
                chat_peer_id=chat_peer_id,
                preloaded_through_timestamp=parse_iso8601_timestamp(timestamp_value),
                preloaded_through_message_id=(
                    int(flask.request.args.get("message_id"))
                    if flask.request.args.get("message_id") is not None
                    else None
                ),
                sqlalchemy_session_maker=sqlalchemy_session_maker,
            )
        except ValueError as exc:
            return flask.Response(str(exc), status=400)
        except LookupError as exc:
            return flask.Response(str(exc), status=404)
        return flask.jsonify({"checkpoint": serialize_preload_checkpoint(checkpoint)})

    @flask_app.route("/preload_checkpoints/clear", methods=["POST"])
    def clear_preload_checkpoints():
        try:
            chat_peer_id = resolve_checkpoint_chat_peer_id(require_target=False)
        except ValueError as exc:
            return flask.Response(str(exc), status=400)
        except LookupError as exc:
            return flask.Response(str(exc), status=404)
        if chat_peer_id is None:
            deleted = clear_all_preload_checkpoints(sqlalchemy_session_maker)
            return flask.jsonify({"deleted": deleted})
        deleted = clear_preload_checkpoint(chat_peer_id, sqlalchemy_session_maker)
        return flask.jsonify({"chat_peer_id": chat_peer_id, "deleted": deleted})

    consecutive_health_failures = 0
    suicide_after_consecutive_health_failures = int(
        os.getenv("SUICIDE_AFTER_CONSECUTIVE_HEALTH_FAILURES", "0")
    )

    @flask_app.route("/health", methods=["GET"])
    @retry(
        retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)),
        stop=stop_after_attempt(3),
    )
    def health():
        returned = actual_health()
        if returned:
            returned_status_code = getattr(returned, "status_code")
            nonlocal consecutive_health_failures
            if not str(returned_status_code).startswith("2"):
                consecutive_health_failures = consecutive_health_failures + 1
            else:
                consecutive_health_failures = 0
            if (
                suicide_after_consecutive_health_failures
                and consecutive_health_failures
                >= suicide_after_consecutive_health_failures
            ):
                logger.critical(
                    "Suiciding app, health check failed consecutively for %s times!",
                    consecutive_health_failures,
                    exc_info=True,
                )
                os._exit(1)
        return returned

    def actual_health():
        logger.debug("Health endpoint called")
        if not loop.is_running():
            return log_and_return_500("Event Loop not running")
        if client is None:
            return log_and_return_500("Client not initialized")
        if bot is not None and bot.client is not None and not bot.client.is_connected():
            return log_and_return_500("Bot not connected")
        if not client.is_connected():
            return log_and_return_500("Client not connected")
        try:
            logger.debug("Querying database on health endpoint")
            with sqlalchemy_session_maker.begin() as sqlalchemy_session:
                sqlalchemy_session.execute(select(sqlalchemy.literal(1)))
        except Exception as e:
            return log_and_return_500(f"Database Error on health query: {e}")
        logger.debug("Checking Telegram Client Communication")
        try:
            asyncio.run_coroutine_threadsafe(client.is_user_authorized(), loop).result()
        except Exception as e:
            return log_and_return_500(
                f"Telegram Error while checking Telegram Client Communication: {e}"
            )
        if bot is not None and bot.client is not None and bot.client.is_connected():
            logger.debug("Checking Telegram Bot Communication")
            try:
                asyncio.run_coroutine_threadsafe(
                    bot.client.is_user_authorized(), loop
                ).result()
            except Exception as e:
                return log_and_return_500(
                    f"Telegram Error while checking Telegram Bot Communication: {e}"
                )
        logger.debug("Returning success from health check")
        return flask.Response(status=204)

    def log_and_return_500(message: str):
        logger.error("%s | %s", message, format_process_runtime_snapshot(), exc_info=True)
        return flask.Response(message, status=500)

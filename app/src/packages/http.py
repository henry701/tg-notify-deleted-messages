"""HTTP/Flask application setup and route definitions."""

import asyncio
import concurrent
import logging
import os

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
from packages.models.root.TelegramMessage import TelegramMessage

logger = logging.getLogger("tgdel-http")


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

                preload_future.add_done_callback(handle_preload_result)
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
                > suicide_after_consecutive_health_failures
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
                sqlalchemy_session.execute(select(TelegramMessage).limit(1))
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
        logger.error(message, exc_info=True)
        return flask.Response(message, status=500)

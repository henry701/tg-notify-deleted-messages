#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import functools
import os
import signal
import threading
import time

import flask

from sqlalchemy.sql.selectable import Select
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError
from telethon.utils import resolve_id
from packages.db_helpers import create_database, get_db_url

from packages.env_helpers import require_env

from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType

import sqlalchemy
from alchemysession import AlchemySessionContainer
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import delete, select

from telethon import TelegramClient, events
import telethon

import contextlib

from telethon.errors import SessionPasswordNeededError

from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Iterator, List, Tuple, Union
from telethon.events import NewMessage, MessageDeleted

from packages.models.root.TelegramMessage import TelegramMessage
from packages.models import Base

from packages.bot_assistant import BotAssistant


import nest_asyncio

import asyncio

from distutils.util import strtobool

from packages.telegram_helpers import build_telegram_peer, format_default_message_text, format_default_unknown_message_text, to_telethon_input_peer

async def add_event_handlers(client : TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Callable[[TelegramMessage, TelegramClient], Awaitable[Any]], notify_unknown_message : Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]):
    new_message_event = events.NewMessage(incoming=True, outgoing=bool(strtobool(os.getenv('NOTIFY_OUTGOING_MESSAGES', 'True'))))
    client.add_event_handler(get_on_new_message(sqlalchemy_session_maker=sqlalchemy_session_maker, client=client), new_message_event)
    client.add_event_handler(get_on_message_deleted(client=client, sqlalchemy_session_maker=sqlalchemy_session_maker, notify_message_deletion=notify_message_deletion, notify_unknown_message=notify_unknown_message), events.MessageDeleted())

def get_on_message_deleted(client: TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Callable[[TelegramMessage, TelegramClient], Awaitable[Any]], notify_unknown_message : Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]):

    ignore_channels = bool(strtobool(os.getenv("IGNORE_CHANNELS", '0')))
    ignore_groups = bool(strtobool(os.getenv("IGNORE_GROUPS", '0')))
    ignore_megagroups = bool(strtobool(os.getenv("IGNORE_MEGAGROUPS", '0')))
    ignore_gigagroups = bool(strtobool(os.getenv("IGNORE_GIGAGROUPS", '0')))

    async def on_message_deleted(event: MessageDeleted.Event):

        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            (messages, query, unloaded_ids, filtered_away_ids) = await load_messages_from_event(
                event,
                client,
                sqlalchemy_session,
                ignore_channels,
                ignore_groups,
                ignore_megagroups,
                ignore_gigagroups
        )

        deleted_messages_count = len(event.deleted_ids)
        deleted_messages_count_str = str(deleted_messages_count)

        db_messages_count = len(messages)
        db_messages_count_str = str(db_messages_count)

        filtered_away_messages_count = len(filtered_away_ids)
        filtered_away_messages_count_str = str(filtered_away_messages_count)
        
        logging.info(
            "Got {deleted_messages_count} deleted messages. Has matching in DB: {db_messages_count}. Filtered away: {filtered_away_messages_count}".format(
                deleted_messages_count=deleted_messages_count_str,
                db_messages_count=db_messages_count_str,
                filtered_away_messages_count=filtered_away_messages_count_str,
            )
        )

        if deleted_messages_count > db_messages_count + filtered_away_messages_count:
            try:
                logging.warning(
                    "Got {deleted_messages_count} deleted messages but only found {db_messages_count} (with {filtered_away_messages_count} filtered away) matching in database! Query: {query_str}".format(
                        deleted_messages_count=deleted_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        filtered_away_messages_count=filtered_away_messages_count_str,
                        query_str=str(query.compile(compile_kwargs={'literal_binds': True}))
                    )
                )
            except Exception as e:
                logging.error(
                    "Error while logging missing deleted message (has {db_messages_count} of {deleted_messages_count}, with {filtered_away_messages_count} filtered away): {e}".format(
                        deleted_messages_count=deleted_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        filtered_away_messages_count=filtered_away_messages_count_str,
                        e=e
                    )
                )

        awaitables : List[Awaitable[Any]] = []
        for message in messages:
            awaitables.append(notify_message_deletion(message, client))
        if unloaded_ids and len(unloaded_ids):
            awaitables.append(notify_unknown_message(unloaded_ids, event, client))
        if len(awaitables) > 0:
            await asyncio.gather(*awaitables)

    return on_message_deleted

def get_on_new_message(sqlalchemy_session_maker : sessionmaker, client : TelegramClient):

    ignore_channels = bool(strtobool(os.getenv("IGNORE_CHANNELS", '0')))
    ignore_groups = bool(strtobool(os.getenv("IGNORE_GROUPS", '0')))
    ignore_megagroups = bool(strtobool(os.getenv("IGNORE_MEGAGROUPS", '0')))
    ignore_gigagroups = bool(strtobool(os.getenv("IGNORE_GIGAGROUPS", '0')))

    async def on_new_message(event: NewMessage.Event):

        logging.debug(f"on_new_message: {event}")

        message : telethon.tl.custom.message.Message = event.message
        
        should_ignore : bool = await should_ignore_incoming_message(
            message,
            ignore_channels,
            ignore_groups,
            ignore_megagroups,
            ignore_gigagroups,
        )

        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            orm_message = TelegramMessage(
                id = message.id,
                from_peer = await build_telegram_peer(message.from_id, client, sqlalchemy_session),
                chat_peer = await build_telegram_peer(message.peer_id, client, sqlalchemy_session),
                text = None if should_ignore else message.message,
                media = None if should_ignore else message.media,
                timestamp = message.date
            )
            sqlalchemy_session.add(orm_message)

    return on_new_message

async def should_ignore_incoming_message(
        message : telethon.tl.custom.message.Message,
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
    ) -> bool:
    chat : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None] = await message.get_chat() # type: ignore
    return await should_ignore_message_chat(
        chat,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
    )

async def should_ignore_deleted_message(
        telegram_message : TelegramMessage,
        client : TelegramClient,
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
    ) -> bool:
    peer_entity : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None] = await build_peer_entity(telegram_message.chat_peer, client)
    return await should_ignore_message_chat(
        peer_entity,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
    )

# https://docs.telethon.dev/en/stable/concepts/chats-vs-channels.html
# https://core.telegram.org/constructor/channel
async def should_ignore_message_chat(
        peer_entity : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None],
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
    ):
    if peer_entity is None:
        return False
    if ignore_channels:
        if isinstance(peer_entity, (telethon.types.PeerChannel, telethon.types.Channel)) and peer_entity.broadcast:
            return True
    if ignore_groups:
        if isinstance(peer_entity, (telethon.types.PeerChat, telethon.types.Chat)):
            return True
    if ignore_megagroups:
        if isinstance(peer_entity, (telethon.types.PeerChannel, telethon.types.Channel)) and peer_entity.megagroup and not peer_entity.gigagroup:
            return True
    if ignore_gigagroups:
        if isinstance(peer_entity, (telethon.types.PeerChannel, telethon.types.Channel)) and peer_entity.gigagroup:
            return True
    return False

async def build_peer_entity(peer : TelegramPeer, client : TelegramClient):
    if peer is None:
        return None
    input_peer = to_telethon_input_peer(peer)
    if input_peer is None:
        return None
    return await client.get_entity(input_peer)

async def load_messages_from_event(
        event: MessageDeleted.Event,
        client : TelegramClient,
        sqlalchemy_session : Session,
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
    ) -> Tuple[List[TelegramMessage], Select, List[int], List[int]]:
    
    logging.debug(f"Searching for messages in {event.deleted_ids}")

    the_query = select(TelegramMessage).where(TelegramMessage.id.in_(event.deleted_ids))
    
    input_chat_id, unused = resolve_id(event.chat_id) if event.chat_id is not None else (None, None)
    
    if input_chat_id is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.peer_id == input_chat_id))

    input_chat = await event.get_input_chat()
    chat_peer_type = PeerType.from_type(type(input_chat))
    if chat_peer_type is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.type == chat_peer_type))

    db_results : List[TelegramMessage] = list(sqlalchemy_session.execute(the_query).scalars().all())
    loaded_ids = [int(str(message.id)) for message in db_results]
    unloaded_ids = [msg_id for msg_id in event.deleted_ids if msg_id not in loaded_ids]

    filtered_results = await filter_deleted_messages_for_event(
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        client,
        db_results
    )
    
    filtered_away_ids = [int(str(message.id)) for message in db_results if message not in filtered_results]

    return (filtered_results, the_query, unloaded_ids, filtered_away_ids)

async def filter_deleted_messages_for_event(
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
        client : TelegramClient,
        db_results : List[TelegramMessage],
    ) -> List[TelegramMessage]:
    return [
        message for message in db_results
        if not await should_ignore_deleted_message(
            message,
            client,
            ignore_channels,
            ignore_groups,
            ignore_megagroups,
            ignore_gigagroups
        )
    ]

async def clean_old_messages_loop(sqlalchemy_session_maker : sessionmaker, seconds_interval : int, ttl : timedelta, stop_event : asyncio.Event):
    logging.info('Starting Clean Old Messages Loop')
    try:
        while True:
            try:
                delete_from_time = datetime.now(tz=timezone.utc) - ttl
                with sqlalchemy_session_maker.begin() as sqlalchemy_session:
                    res = sqlalchemy_session.execute(
                        delete(TelegramMessage).where(TelegramMessage.timestamp < delete_from_time)
                    )
                count = res.rowcount
                logging.info(
                    f"Deleted {str(count)} messages older than {str(delete_from_time)} from DB. Sleeping for {seconds_interval} seconds..."
                )
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop_event.wait(), seconds_interval)
                if stop_event.is_set():
                    logging.info('Stop event is set, breaking from Clean Old Messages Inner Loop!')
                    break
            except Exception as e:
                logging.critical("Error on Clean Old Messages Inner Loop Handler! {e}".format(e=e))
    except Exception as e:
        logging.critical("Error on Clean Old Messages Outer Loop Handler! {e}".format(e=e))
    finally:
        logging.info('Exiting Clean Old Messages Loop')

def get_base_notify_message_deletion(sqlalchemy_session_maker : sessionmaker) -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def base_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
        logging.debug("base_notify_message_deletion")
        with sqlalchemy_session_maker.begin() as session:
                session.add(message)
                message.deleted = True # type: ignore
    return base_notify_message_deletion

def get_default_notify_message_deletion() -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def default_notify_message_deletion(message : TelegramMessage, client: TelegramClient):
        logging.debug("default_notify_message_deletion")
        await client.send_message(
            entity="me",
            message=await format_default_message_text(client, message), # type: ignore
            file=message.media # type: ignore
        )
    return default_notify_message_deletion

def get_default_notify_unknown_message() -> Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]:
    async def default_notify_unknown_message(message_ids : List[int], event : MessageDeleted.Event, client: TelegramClient):
        logging.debug("default_notify_unknown_message")
        await client.send_message(
            entity="me",
            message=await format_default_unknown_message_text(client, message_ids, event)  # type: ignore
        )
    return default_notify_unknown_message

def ask_exit(signame, loop : asyncio.AbstractEventLoop, additional):
    logging.warning("got signal %s: exiting" % signame)
    if additional:
        logging.warning("running user-provided cleanupper")
        try:
            asyncio.run_coroutine_threadsafe(additional(), loop).result()
        except RuntimeError as e:
            if "Event loop stopped before Future completed" not in str(e):
                raise
        logging.warning("ran user-provided cleanupper")
    logging.warning("cancelling all tasks")
    for task in asyncio.all_tasks(loop):
        task.cancel()
    logging.warning("cancelled all tasks")

async def make_client(alchemy_telegram_container : AlchemySessionContainer, telegram_api_id, telegram_api_hash, session_id, loop : asyncio.AbstractEventLoop):
    telegram_session = alchemy_telegram_container.new_session(session_id)
    client = TelegramClient(session=telegram_session, api_id=telegram_api_id, api_hash=telegram_api_hash, loop=loop)
    logging.info('Connecting Telegram Client')
    try:
        await client.connect()
    except AuthKeyDuplicatedError:
        telegram_session.delete()
        telegram_session = alchemy_telegram_container.new_session(session_id)
        client = TelegramClient(session=telegram_session, api_id=telegram_api_id, api_hash=telegram_api_hash)
        await client.connect()
    logging.info('Telegram Client Connected!')
    return client

def add_signal_handlers(loop, closer):
    for signame in {'SIGINT', 'SIGTERM'}:
        loop.add_signal_handler(
            getattr(signal, signame),
            functools.partial(ask_exit, signame, loop, closer)
        )

async def configure_bot(alchemy_telegram_container, telegram_api_id, telegram_api_hash, target_chat, session_id):
    logging.info('Configuring Bot')
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    configured_notify_message_deletion = None
    configured_notify_unknown_message = None
    bot = None
    if telegram_bot_token is not None:
        if target_chat is None or target_chat == "me":
            logging.critical('Must provide TARGET_CHAT (except "me") if you want to use bot assistant!')
            exit(1)
        logging.info('Using bot for message notification')
        bot = BotAssistant(
            int(target_chat) if bool(strtobool(os.getenv("TARGET_CHAT_IS_ID", '0'))) else target_chat,
            telegram_api_id,
            telegram_api_hash,
            telegram_bot_token,
            session_maker = lambda: alchemy_telegram_container.new_session(session_id + "_bot")
        )
        await bot.__aenter__()
        configured_notify_message_deletion = bot.notify_message_deletion
        configured_notify_unknown_message = bot.notify_unknown_message
    logging.info('Configured Bot')
    return configured_notify_message_deletion,configured_notify_unknown_message,bot

async def client_main_loop_job(stop_event, sqlalchemy_session_maker, configured_notify_message_deletion, configured_notify_unknown_message, client):
    if not configured_notify_message_deletion:
        configured_notify_message_deletion = get_default_notify_message_deletion()
    if not configured_notify_unknown_message:
        configured_notify_unknown_message = get_default_notify_unknown_message()
    base_notify_message_deletion = get_base_notify_message_deletion(sqlalchemy_session_maker=sqlalchemy_session_maker)
    async def actual_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
        await base_notify_message_deletion(message, client)
        await configured_notify_message_deletion(message, client)
    logging.info('Adding event handlers')
    await add_event_handlers(client, sqlalchemy_session_maker, actual_notify_message_deletion, configured_notify_unknown_message)
    logging.info('Added event handlers')
    await clean_old_messages_loop(
        sqlalchemy_session_maker=sqlalchemy_session_maker,
        seconds_interval=int(os.getenv("CLEAN_OLD_MESSAGES_SECONDS_INTERVAL", 900)),
        ttl=timedelta(days=int(os.getenv('MESSAGES_TTL_DAYS', 14))),
        stop_event=stop_event
    )

def create_app_and_start_jobs() -> Tuple[flask.Flask, Callable[[], None]]:

    loop = asyncio.events.new_event_loop()
    nest_asyncio.apply(loop)

    stop_event : Union[asyncio.Event, None] = None
    client : Union[TelegramClient, None] = None
    bot : Union[BotAssistant, None] = None

    async def closer():
        nonlocal stop_event
        nonlocal client
        nonlocal bot
        if stop_event is not None:
            stop_event.set()
        if client is not None:
            disconnecter_coro = client.disconnect()
            if disconnecter_coro is not None:
                await disconnecter_coro
            client = None
        if bot is not None:
            await bot.__aexit__(None, None, None)
        count = 0
        while asyncio.all_tasks(loop) and count < 10:
            await asyncio.sleep(1)
            count += 1
    
    def sync_closer():
        ask_exit('NO-SIGNAL-EXTERNAL', loop, closer)

    add_signal_handlers(loop, closer)

    database_url = get_db_url()

    old_sqlalchemy_engine = create_engine(database_url, False)
    alchemy_telegram_container = AlchemySessionContainer(engine = old_sqlalchemy_engine, table_base=Base, manage_tables=False, table_prefix=os.getenv("SESSION_TABLE_PREFIX", 'thon_'))
    alchemy_telegram_container.core_mode = True

    sqlalchemy_engine = create_engine(database_url, True)
    sqlalchemy_session_maker = sessionmaker(bind=sqlalchemy_engine, future=True, expire_on_commit=False)

    create_database(sqlalchemy_engine)

    telegram_api_id = require_env("TELEGRAM_API_ID")
    telegram_api_hash = require_env("TELEGRAM_API_HASH")

    target_chat = os.getenv("TARGET_CHAT", "me")

    session_id = require_env("SESSION_ID")

    configured_notify_message_deletion, configured_notify_unknown_message, bot = loop.run_until_complete(configure_bot(alchemy_telegram_container, telegram_api_id, telegram_api_hash, target_chat, session_id))

    client = loop.run_until_complete(make_client(alchemy_telegram_container, telegram_api_id, telegram_api_hash, session_id, loop))

    def worker_function(loop : asyncio.AbstractEventLoop, sync_closer : Callable[[], Any]):
        logging.info("Entering worker function!")
        try:
            asyncio.set_event_loop(loop)
            nonlocal stop_event
            stop_event = asyncio.Event()
            loop.run_forever()
        except Exception as e:
            logging.critical("Error on worker function! {e}".format(e=e))
            sync_closer()
        finally:
            logging.info("Exiting worker function!")
    worker_thread = threading.Thread(target=worker_function, args=(loop, sync_closer), name='loop-app-client-bgthread')
    worker_thread.start()

    while stop_event is None and worker_thread.is_alive:
        time.sleep(0)

    if stop_event is None:
        raise RuntimeError("Worker thread died before setting stop_event!")

    asyncio.run_coroutine_threadsafe(
        client_main_loop_job(stop_event, sqlalchemy_session_maker, configured_notify_message_deletion, configured_notify_unknown_message, client),
        loop
    )

    flask_app = create_app(
        client,
        bot,
        loop,
        sqlalchemy_session_maker
    )

    logging.info("Returning from create_app_and_start_jobs")
    return (flask_app, sync_closer)

def create_engine(database_url : str, future : bool):
    return sqlalchemy.create_engine(
        database_url,
        echo=False,
        future=future, # type: ignore
        pool_size=10,
        max_overflow=2,
        pool_recycle=300,
        pool_pre_ping=True,
        pool_use_lifo=True,
        connect_args={
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        }
    )

def create_app(client : Union[TelegramClient, None], bot : Union[BotAssistant, None], loop : asyncio.AbstractEventLoop, sqlalchemy_session_maker : sessionmaker) -> flask.Flask:

    if client is None:
        raise ValueError('Client not initialized!')

    flask_app = flask.Flask(__name__)

    phone = require_env("PHONE_NUMBER")

    sent_code : Union[telethon.types.auth.SentCode, None] = None

    add_informative_routes(client, bot, flask_app, loop, sqlalchemy_session_maker)

    @flask_app.route('/send_code', methods=['GET'])
    def send_code():
        logging.info('Sending code request')
        nonlocal sent_code
        sent_code = asyncio.run_coroutine_threadsafe(client.send_code_request(phone=phone), loop).result()
        logging.info('Sent code request')
        return flask.Response(status=204)

    @flask_app.route('/auth', methods=['GET'])
    def auth():
        nonlocal sent_code
        logging.info('Auth request received')
        code = flask.request.args.get("code")
        password = flask.request.args.get("password")
        if not sent_code:
            return flask.Response("Missing send_code request", status=401)
        if not code and not password:
            return flask.Response("Missing code and password queryParameter. Either one or the other should be present!", status=403)
        if code and password:
            return flask.Response("Both code and password parameters present, but either one or the other should be present!", status=400)
        try:
            logging.info('Attempting to sign in')
            sign_in_result = asyncio.run_coroutine_threadsafe(
                client.sign_in(
                    phone_code_hash=sent_code.phone_code_hash,
                    phone=phone,
                    code=code, # type: ignore
                    password=password, # type: ignore
                ),
                loop
            ).result()
            if isinstance(sign_in_result, telethon.types.User):
                return flask.Response(status=204)
            if isinstance(sign_in_result, telethon.types.auth.SentCode):
                sent_code = sign_in_result
                return flask.Response("Sent code, but auth is still incomplete!", status=401)
            return flask.Response("Unknown return from client.sign_in, probable Telethon or application bug!", status=500)
        except (telethon.errors.rpcerrorlist.AuthKeyUnregisteredError, telethon.errors.rpcerrorlist.AuthKeyDuplicatedError):
            return flask.Response("Missing new send_code request. Unregistered or duplicate!", status=401)
        except SessionPasswordNeededError:
            return flask.Response("Password needed!", status=401)

    return flask_app

def add_informative_routes(client : TelegramClient, bot : Union[BotAssistant, None], flask_app : flask.Flask, loop : asyncio.AbstractEventLoop, sqlalchemy_session_maker : sessionmaker):

    @flask_app.route('/is_bot_connected', methods=['GET'])
    def is_bot_connected():
        return flask.Response(str(bot is not None and bot.client is not None and bot.client.is_connected()), status=200)

    @flask_app.route('/is_connected', methods=['GET'])
    def is_connected():
        return flask.Response(str(client.is_connected()), status=200)
    
    @flask_app.route('/is_bot_authorized', methods=['GET'])
    def is_bot_authorized():
        return flask.Response(str(bot is not None and bot.client is not None and asyncio.run_coroutine_threadsafe(bot.client.is_user_authorized(), loop).result()), status=200)

    @flask_app.route('/is_authorized', methods=['GET'])
    def is_authorized():
        return flask.Response(str(asyncio.run_coroutine_threadsafe(client.is_user_authorized(), loop).result()), status=200)

    @flask_app.route('/save_sessions', methods=['GET'])
    def save_sessions():
        client.session.save()
        if bot is not None and bot.client is not None:
            bot.client.session.save()
        return flask.Response(status=204)

    @flask_app.route('/health', methods=['GET'])
    def health():
        logging.debug("Health endpoint called")
        if not loop.is_running():
            return log_and_return_500("Event Loop not running")
        if client is None:
            return log_and_return_500("Client not initialized")
        if bot is not None and bot.client is not None and not bot.client.is_connected():
            return log_and_return_500("Bot not connected")
        if not client.is_connected():
            return log_and_return_500("Client not connected")
        try:
            with sqlalchemy_session_maker.begin() as sqlalchemy_session:
                sqlalchemy_session.execute(
                    select(TelegramMessage).limit(1)
                )
        except Exception as e:
            return log_and_return_500("Database Error on health query: {e}".format(e=e))
        return flask.Response(status=204)
    
    def log_and_return_500(message : str):
        logging.error(message)
        return flask.Response(message, status=500)

def main():
    app, closer = create_app_and_start_jobs()
    port = int(require_env("PORT"))
    app.run(port=port, host='0.0.0.0')
    closer()

if __name__ == "__main__":
    main()

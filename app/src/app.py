#!/usr/bin/env python
# -*- coding: utf-8 -*-

from asyncio.base_events import BaseEventLoop
import logging
import functools
import os
import signal
import threading

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

import concurrent.futures

from telethon import TelegramClient, events
import telethon

import contextlib

from telethon.errors import SessionPasswordNeededError

from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, List, Tuple
from telethon.events import NewMessage, MessageDeleted
from telethon.tl.types import Message

from packages.models.root.TelegramMessage import TelegramMessage
from packages.models import Base

from packages.bot_assistant import BotAssistant

from urllib.parse import urlparse

import nest_asyncio

import asyncio
from asyncio.tasks import Task

from distutils.util import strtobool

from packages.telegram_helpers import build_telegram_peer, format_default_message_text, format_default_unknown_message_text

async def add_event_handlers(client : TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Callable[[TelegramMessage, TelegramClient], Awaitable[Any]], notify_unknown_message : Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]):
    new_message_event = events.NewMessage(incoming=True, outgoing=bool(strtobool(os.getenv('NOTIFY_OUTGOING_MESSAGES', 'True'))))
    client.add_event_handler(get_on_new_message(sqlalchemy_session_maker=sqlalchemy_session_maker, client=client), new_message_event)
    client.add_event_handler(get_on_message_deleted(client=client, sqlalchemy_session_maker=sqlalchemy_session_maker, notify_message_deletion=notify_message_deletion, notify_unknown_message=notify_unknown_message), events.MessageDeleted())

def get_on_message_deleted(client: TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Callable[[TelegramMessage, TelegramClient], Awaitable[Any]], notify_unknown_message : Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]):

    async def on_message_deleted(event: MessageDeleted.Event):

        with sqlalchemy_session_maker() as sqlalchemy_session:
            (messages, query, unloaded_ids) = await load_messages_from_event(event, sqlalchemy_session)
            sqlalchemy_session.commit()

        deleted_messages_count = len(event.deleted_ids)
        deleted_messages_count_str = str(deleted_messages_count)

        db_messages_count = len(messages)
        db_messages_count_str = str(db_messages_count)
        
        logging.info(
            "Got {deleted_messages_count} deleted messages. Has in DB: {db_messages_count}.".format(
                deleted_messages_count=deleted_messages_count_str,
                db_messages_count=db_messages_count_str,
            )
        )

        if deleted_messages_count > db_messages_count:
            try:
                logging.warning(
                    "Got {deleted_messages_count} deleted messages but only found {db_messages_count} in database! Query: {query_str}".format(
                        deleted_messages_count=deleted_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        query_str=str(query.compile(compile_kwargs={'literal_binds': True}))
                    )
                )
            except Exception as e:
                logging.error(
                    "Error while logging missing deleted message (has {db_messages_count} of {deleted_messages_count}): {e}".format(
                        deleted_messages_count=deleted_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        e=e
                    )
                )

        proms : List[Task[Message]] = []
        for message in messages:
            proms.append(asyncio.run_coroutine_threadsafe(notify_message_deletion(message, client), client.loop))
        if unloaded_ids and len(unloaded_ids):
            proms.append(asyncio.run_coroutine_threadsafe(notify_unknown_message(unloaded_ids, event, client), client.loop))
        if proms:
            await asyncio.gather(*proms)

    return on_message_deleted

def get_on_new_message(sqlalchemy_session_maker : sessionmaker, client : TelegramClient):
    async def on_new_message(event: NewMessage.Event):
        logging.debug(f"on_new_message: {event}")
        logging.debug("START cache lib telethon bad")
        # Cache Lib (Telethon bad)
        await event.get_input_sender()
        await event.get_input_chat()
        logging.debug("END cache lib telethon bad")
        with sqlalchemy_session_maker() as sqlalchemy_session:
            message : telethon.tl.custom.message.Message = event.message
            orm_message = TelegramMessage(
                id = message.id,
                from_peer = await build_telegram_peer(event.from_id, client, sqlalchemy_session),
                chat_peer = await build_telegram_peer(event.peer_id, client, sqlalchemy_session),
                text = message.message,
                media = message.media,
                timestamp = message.date
            )
            sqlalchemy_session.add(orm_message)
            sqlalchemy_session.commit()
    return on_new_message

async def load_messages_from_event(event: MessageDeleted.Event, sqlalchemy_session : Session) -> Tuple[List[TelegramMessage], Select, List[int]]:
    logging.debug(f"Searching for messages in {event.deleted_ids}")
    input_chat = await event.get_input_chat()
    chat_peer_type = PeerType.from_type(type(input_chat))
    input_chat_id, unused = resolve_id(event.chat_id) if event.chat_id is not None else (None, None)
    the_query = select(TelegramMessage).where(TelegramMessage.id.in_(event.deleted_ids))
    if input_chat_id is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.peer_id == input_chat_id))
    if chat_peer_type is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.type == chat_peer_type))
    db_results = sqlalchemy_session.execute(the_query).scalars().all()
    loaded_ids = map(lambda x: x.id, db_results)
    unloaded_ids = [msg_id for msg_id in event.deleted_ids if msg_id not in loaded_ids]
    return (db_results, the_query, unloaded_ids)

async def clean_old_messages_loop(sqlalchemy_session_maker : sessionmaker, seconds_interval : int, ttl : timedelta, stop_event : asyncio.Event):
    logging.debug('Starting Clean Old Messages Loop')
    while True:
        delete_from_time = datetime.now(tz=timezone.utc) - ttl
        with sqlalchemy_session_maker() as sqlalchemy_session:
            res = sqlalchemy_session.execute(
                delete(TelegramMessage).where(TelegramMessage.timestamp < delete_from_time)
            )
            sqlalchemy_session.commit()
            count = res.rowcount
        logging.info(
            f"Deleted {str(count)} messages older than {str(delete_from_time)} from DB. Sleeping for {seconds_interval} seconds..."
        )
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop_event.wait(), seconds_interval)
        if stop_event.is_set():
            break
    logging.debug('Exiting Clean Old Messages Loop')

def get_base_notify_message_deletion(sqlalchemy_session_maker : sessionmaker) -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def base_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
        logging.debug("base_notify_message_deletion")
        with sqlalchemy_session_maker() as session:
                session.add(message)
                message.deleted = True
                session.commit()
    return base_notify_message_deletion

def get_default_notify_message_deletion() -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def default_notify_message_deletion(message : TelegramMessage, client: TelegramClient):
        logging.debug("default_notify_message_deletion")
        await client.send_message(
            entity="me",
            message=await format_default_message_text(client, message),
            file=message.media
        )
    return default_notify_message_deletion

def get_default_notify_unknown_message() -> Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]:
    async def default_notify_unknown_message(message_ids : List[int], event : MessageDeleted.Event, client: TelegramClient):
        logging.debug("default_notify_unknown_message")
        await client.send_message(
            entity="me",
            message=await format_default_unknown_message_text(client, message_ids, event)
        )
    return default_notify_unknown_message

def ask_exit(signame, loop : BaseEventLoop, additional):
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

async def make_client(alchemy_telegram_container, telegram_api_id, telegram_api_hash, session_id, telegram_session, loop : BaseEventLoop):
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
            int(target_chat) if bool(strtobool(os.getenv("TARGET_CHAT_IS_ID"))) else target_chat,
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
    logging.debug('Before With Client')
    logging.debug('Inside With Client')
    if not configured_notify_message_deletion:
        configured_notify_message_deletion = get_default_notify_message_deletion()
    if not configured_notify_unknown_message:
        configured_notify_unknown_message = get_default_notify_unknown_message()
    base_notify_message_deletion = get_base_notify_message_deletion(sqlalchemy_session_maker=sqlalchemy_session_maker)
    async def actual_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
        await base_notify_message_deletion(message, client)
        await configured_notify_message_deletion(message, client)
    logging.debug('Adding event handlers')
    await add_event_handlers(client, sqlalchemy_session_maker, actual_notify_message_deletion, configured_notify_unknown_message)
    logging.debug('Added event handlers')
    await clean_old_messages_loop(
        sqlalchemy_session_maker=sqlalchemy_session_maker,
        seconds_interval=int(os.getenv("CLEAN_OLD_MESSAGES_SECONDS_INTERVAL", 900)),
        ttl=timedelta(days=int(os.getenv('MESSAGES_TTL_DAYS', 14))),
        stop_event=stop_event
    )
    logging.debug('Client is exiting scope')

def create_app_and_start_jobs():

    loop = asyncio.events.new_event_loop()
    nest_asyncio.apply(loop)

    stop_event = asyncio.Event()

    client = None
    bot = None
    executor = None

    async def closer():
        stop_event.set()
        if client:
            await client.__aexit__(None, None, None)
        if bot:
            await bot.__aexit__(None, None, None)
        if executor:
            executor.shutdown(cancel_futures=True, wait=False)
        count = 0
        while asyncio.all_tasks(loop) and count < 10:
            await asyncio.sleep(1)
            count += 1
    
    def sync_closer():
        ask_exit('NO-SIGNAL-EXTERNAL', loop, closer)

    add_signal_handlers(loop, closer)

    database_url = get_db_url()

    old_sqlalchemy_engine = sqlalchemy.create_engine(database_url, echo=False, future=False)
    alchemy_telegram_container = AlchemySessionContainer(engine = old_sqlalchemy_engine, table_base=Base, manage_tables=False, table_prefix=os.getenv("SESSION_TABLE_PREFIX", 'thon_'))

    sqlalchemy_engine = sqlalchemy.create_engine(database_url, echo=False, future=True)
    sqlalchemy_session_maker = sessionmaker(bind=sqlalchemy_engine, future=True, expire_on_commit=False)

    create_database(sqlalchemy_engine)

    telegram_api_id = require_env("TELEGRAM_API_ID")
    telegram_api_hash = require_env("TELEGRAM_API_HASH")
    
    target_chat = os.getenv("TARGET_CHAT", "me")

    session_id = require_env("SESSION_ID")

    configured_notify_message_deletion, configured_notify_unknown_message, bot = loop.run_until_complete(configure_bot(alchemy_telegram_container, telegram_api_id, telegram_api_hash, target_chat, session_id))

    telegram_session = alchemy_telegram_container.new_session(session_id)

    client = loop.run_until_complete(make_client(alchemy_telegram_container, telegram_api_id, telegram_api_hash, session_id, telegram_session, loop))

    def worker_function(loop : BaseEventLoop):
        logging.info("Entering worker function!")
        asyncio.set_event_loop(loop)
        loop.run_forever()
        logging.info("Exiting worker function!")
    worker_thread = threading.Thread(target=worker_function, args=(loop,), name='loop-app-client-bgthread')
    worker_thread.start()

    asyncio.run_coroutine_threadsafe(
        client_main_loop_job(stop_event, sqlalchemy_session_maker, configured_notify_message_deletion, configured_notify_unknown_message, client),
        loop
    )

    flask_app = create_app(client, loop)

    logging.info("Returning from create_app_and_start_jobs")
    return (flask_app, sync_closer)

def create_app(client, loop : asyncio.AbstractEventLoop):
    flask_app = flask.Flask(__name__)

    port = int(require_env("PORT"))
    host = os.getenv("HOST", "<host>")
    use_https = bool(strtobool(os.getenv("USE_HTTPS", "0")))
    use_external_port = bool(strtobool(os.getenv("USE_EXTERNAL_PORT", "0")))
    phone = require_env("PHONE_NUMBER")

    @flask_app.route('/send_code', methods=['GET'])
    def send_code():
        logging.info('Sending code request')
        asyncio.run_coroutine_threadsafe(client.send_code_request(phone=phone), loop).result()
        logging.info('Sent code request')
        logging.info(f"To continue, send GET request to following URL: http{'s' if use_https else ''}://{host}{f':{port}' if use_external_port else ''}/auth?code=<code here>&password=<2fa pass if enabled>")
        return flask.Response(status=204)
    
    @flask_app.route('/auth', methods=['GET'])
    def auth():
        logging.info('Auth request received')
        code = flask.request.args.get("code")
        password = flask.request.args.get("password")
        if not code:
            return flask.Response(status=403)
        try:
            logging.info('Attempting to sign in')
            if asyncio.run_coroutine_threadsafe(client.sign_in(phone=phone, code=code, password=password), loop).result():
                return flask.Response(status=204)
            return flask.Response(status=403)
        except SessionPasswordNeededError:
            return flask.Response(status=401)

    return flask_app

def main():
    app, closer = create_app_and_start_jobs()
    port = int(require_env("PORT"))
    app.run(port=port, host='0.0.0.0')
    closer()

if __name__ == "__main__":
    main()

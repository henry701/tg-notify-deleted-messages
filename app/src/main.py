#!/usr/bin/env python
# -*- coding: utf-8 -*-

from asyncio.base_events import BaseEventLoop
import logging
import functools
import os
import signal
import pathlib

from sqlalchemy.sql.selectable import Select

from packages.env_helpers import load_env, require_env

BASE_DIR = pathlib.Path(__file__).parent.absolute().resolve()
CONF_DIR = (BASE_DIR / '..' / 'conf').absolute().resolve()
load_env(CONF_DIR)
DEFAULT_LOGGING_LEVEL = os.getenv("DEFAULT_LOGGING_LEVEL", logging.INFO)
logging.basicConfig(level=os.getenv("ROOT_LOGGING_LEVEL", DEFAULT_LOGGING_LEVEL), force=True)
logging.getLogger('sqlalchemy').setLevel(os.getenv("SQLALCHEMY_LOGGING_LEVEL", DEFAULT_LOGGING_LEVEL))

sqreen_token = os.getenv("SQREEN_TOKEN")
if sqreen_token:
    sqreen = None
    try:
        import sqreen
    except ImportError:
        logging.warning("Unable to import sqreen module")
    if sqreen:
        sqreen.start()

from sqlalchemy import sql
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.type_api import TypeEngine

from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType

import sqlalchemy
from alchemysession import AlchemySessionContainer
from sqlalchemy.orm import sessionmaker, aliased
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import delete, select
from sqlalchemy import sql
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.type_api import TypeEngine

from telethon import TelegramClient, events
import telethon

import contextlib

from telethon.errors import SessionPasswordNeededError

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Coroutine, List, Tuple, Union
from telethon.events import NewMessage, MessageDeleted
from telethon.hints import Entity, MessageLike
from telethon.tl.types import Message, PeerChannel, PeerChat, PeerUser

from packages.models.root.TelegramMessage import TelegramMessage
from packages.models import Base, encrypt_type_searchable

from packages.bot_assistant import BotAssistant

import sqlalchemy_utils

from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

from urllib.parse import urlparse

import nest_asyncio

import asyncio
from asyncio.tasks import Task

from distutils.util import strtobool

from packages.helpers import build_telegram_peer, format_default_message_text

async def add_event_handlers(client : TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Coroutine[TelegramMessage, TelegramClient, Any]):
    new_message_event = events.NewMessage(incoming=True, outgoing=bool(strtobool(os.getenv('NOTIFY_OUTGOING_MESSAGES', 'True'))))
    client.add_event_handler(get_on_new_message(sqlalchemy_session_maker=sqlalchemy_session_maker, client=client), new_message_event)
    client.add_event_handler(get_on_message_deleted(client=client, sqlalchemy_session_maker=sqlalchemy_session_maker, notify_message_deletion=notify_message_deletion), events.MessageDeleted())

def get_on_message_deleted(client: TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Coroutine[TelegramMessage, TelegramClient, Any]):

    async def on_message_deleted(event: MessageDeleted.Event):

        with sqlalchemy_session_maker() as sqlalchemy_session:
            (messages, query) = await load_messages_from_event(event, sqlalchemy_session)
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
                        query_str=str(query.compile())
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
            proms.append(client.loop.create_task(notify_message_deletion(message, client)))
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

async def load_messages_from_event(event: MessageDeleted.Event, sqlalchemy_session : Session) -> Tuple[List[TelegramMessage], Select]:
    logging.debug(f"Searching for messages in {event.deleted_ids}")
    peer_type = PeerType.from_type(type(await event.get_input_chat()))
    the_query = select(TelegramMessage).where(TelegramMessage.id.in_(event.deleted_ids))
    if event.chat_id is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.peer_id == event.chat_id) or TelegramMessage.from_peer.has(TelegramPeer.peer_id == event.chat_id))
    if peer_type is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.type == peer_type))
    db_results = sqlalchemy_session.execute(the_query).scalars().all()
    return (db_results, the_query)

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

def get_base_notify_message_deletion(sqlalchemy_session_maker : sessionmaker) -> Coroutine[TelegramMessage, TelegramClient, Any]:
    async def base_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
        logging.debug("base_notify_message_deletion")
        with sqlalchemy_session_maker() as session:
                session.add(message)
                message.deleted = True
                session.commit()
    return base_notify_message_deletion

def get_default_notify_message_deletion() -> Coroutine[TelegramMessage, TelegramClient, Any]:
    async def default_notify_message_deletion(message : TelegramMessage, client: TelegramClient):
        logging.debug("default_notify_message_deletion")
        await client.send_message(
            entity="me",
            message=await format_default_message_text(client, message),
            file=message.media
        )
    return default_notify_message_deletion

def ask_exit(signame, loop : BaseEventLoop, additional):
    logging.warning("got signal %s: exiting" % signame)
    if additional:
        logging.warning("running user-provided cleanupper")
        try:
            loop.run_until_complete(additional())
        except RuntimeError as e:
            if not "Event loop stopped before Future completed" in str(e):
                raise
        logging.warning("ran user-provided cleanupper")
    logging.warning("cancelling all tasks")
    for task in asyncio.all_tasks(loop):
        task.cancel()
    logging.warning("cancelled all tasks")

async def main():

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    async def closer():
        stop_event.set()
        if client:
            await client.__aexit__(None, None, None)
        if bot:
            await bot.__aexit__(None, None, None)
        count = 0
        while asyncio.all_tasks(loop) and count < 5:
            await asyncio.sleep(1)
            count += 1

    for signame in {'SIGINT', 'SIGTERM'}:
        loop.add_signal_handler(
            getattr(signal, signame),
            functools.partial(ask_exit, signame, loop, closer))

    database_url = require_env("DATABASE_URL")
    # Heroku Workaround
    database_url = database_url.replace("postgres://", "postgresql://")

    old_sqlalchemy_engine = sqlalchemy.create_engine(database_url, echo=False, future=False)
    alchemy_telegram_container = AlchemySessionContainer(engine = old_sqlalchemy_engine, table_base=Base, manage_tables=False, table_prefix=os.getenv("SESSION_TABLE_PREFIX", 'thon_'))

    sqlalchemy_engine = sqlalchemy.create_engine(database_url, echo=False, future=True)
    sqlalchemy_session_maker = sessionmaker(bind=sqlalchemy_engine, future=True, expire_on_commit=False)

    # Changing this logic for encryption selection requires adaptation of the underlying database, if existing!
    metadata : sqlalchemy.schema.MetaData = Base.metadata
    black = (sqlalchemy_utils.types.encrypted.encrypted_type.StringEncryptedType)
    white = (sqlalchemy.types.String, sqlalchemy.types.LargeBinary)
    def final_predicate(col : Column):
        if col.autoincrement is True:
            return False
        for fk in col.foreign_keys:
            if not encrypt_agg(fk.column):
                return False
        return True
    def white_predicate(col : Column):
        return col.name.endswith('_id') or col.name in ['id', 'phone', ]
    def encrypt_agg(column : Column):
        return not isinstance(column.type, black) and (isinstance(column.type, white) or white_predicate(column)) and final_predicate(column)
    for table in metadata.tables.values():
        for column in table.columns:
            logging.debug(f"Traversing Type: {column.type}")
            if encrypt_agg(column):
                column.type = encrypt_type_searchable(column.type)
    metadata.create_all(sqlalchemy_engine)

    telegram_api_id = require_env("TELEGRAM_API_ID")
    telegram_api_hash = require_env("TELEGRAM_API_HASH")
    
    target_chat = os.getenv("TARGET_CHAT", "me")
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")

    session_id = require_env("SESSION_ID")

    configured_notify_message_deletion = None
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
            session=alchemy_telegram_container.new_session(session_id + "_bot")
        )
        await bot.__aenter__()
        configured_notify_message_deletion = bot.notify_message_deletion

    telegram_session = alchemy_telegram_container.new_session(session_id)

    client = TelegramClient(session=telegram_session, api_id=telegram_api_id, api_hash=telegram_api_hash)
    nest_asyncio.apply(client.loop)
    await client.connect()

    if not await client.is_user_authorized():
        phone = require_env("PHONE_NUMBER")
        logging.info('Sending code request')
        await client.send_code_request(phone=phone)
        logging.info('Sent code request')
        logging.info('Creating HTTP class and starting server...')
        auth_wrapper = { 'code': None, 'password': None }
        class MyHandler(BaseHTTPRequestHandler):
            # Handler for the GET requests
            def do_GET(self):
                logging.info('Get request received')
                query = urlparse(self.path).query
                query_components = dict(qc.split("=") for qc in query.split("&"))
                auth_wrapper['code'] = query_components.get("code")
                auth_wrapper['password'] = query_components.get("password")
                if not auth_wrapper['code']:
                    self.send_response(403)
                    self.end_headers()
                    return
                try:
                    if client.loop.run_until_complete(client.sign_in(phone=phone, code=auth_wrapper['code'], password=auth_wrapper['password'])):
                        self.send_response(204)
                        self.end_headers()
                        return
                    self.send_response(403)
                    self.end_headers()
                except SessionPasswordNeededError:
                    self.send_response(401)
                    self.end_headers()
        port = int(require_env("PORT"))
        host = os.getenv("HOST", "<host>")
        with HTTPServer(('0.0.0.0', port), MyHandler) as httpd:
            use_https = bool(strtobool(os.getenv("USE_HTTPS", "0")))
            use_external_port = bool(strtobool(os.getenv("USE_EXTERNAL_PORT", "0")))
            if use_https:
                httpd.socket = ssl.wrap_socket(httpd.socket, certfile=str((CONF_DIR / 'server.pem').resolve()), server_side=True)
            while not await client.is_user_authorized():
                logging.info(f"To continue, send GET request to following URL: http{'s' if use_https else ''}://{host}{f':{port}' if use_external_port else ''}?code=<code here>&password=<2fa pass if enabled>")
                httpd.handle_request()

    logging.debug('Before With Client')
    async with client:
        logging.debug('Inside With Client')
        if not configured_notify_message_deletion:
            configured_notify_message_deletion = get_default_notify_message_deletion()
        base_notify_message_deletion = get_base_notify_message_deletion(sqlalchemy_session_maker=sqlalchemy_session_maker)
        async def actual_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
            await base_notify_message_deletion(message, client)
            await configured_notify_message_deletion(message, client)
        logging.debug('Adding event handlers')
        await add_event_handlers(client, sqlalchemy_session_maker, actual_notify_message_deletion)
        logging.debug('Added event handlers')
        await clean_old_messages_loop(
            sqlalchemy_session_maker=sqlalchemy_session_maker,
            seconds_interval=int(os.getenv("CLEAN_OLD_MESSAGES_SECONDS_INTERVAL", 900)),
            ttl=timedelta(days=int(os.getenv('MESSAGES_TTL_DAYS', 14))),
            stop_event=stop_event
        )

if __name__ == "__main__":
    asyncio.run(main())
    logging.info("bye!")

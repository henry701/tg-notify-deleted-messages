#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import pathlib

from sqlalchemy import sql
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.type_api import TypeEngine

from packages.env_helpers import load_env, require_env

BASE_DIR = pathlib.Path(__file__).parent.absolute().resolve()
CONF_DIR = (BASE_DIR / '..' / 'conf').absolute().resolve()
load_env(CONF_DIR)
LOGGING_LEVEL = os.getenv("LOGGING_LEVEL", logging.INFO)
logging.basicConfig(level=LOGGING_LEVEL, force=True)

import sqlalchemy
from alchemysession import AlchemySessionContainer
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import delete, select

from telethon import TelegramClient, events
import telethon

from telethon.errors import SessionPasswordNeededError

from datetime import datetime, timedelta, timezone
from typing import Any, Coroutine, List
from telethon.events import NewMessage, MessageDeleted
from telethon.hints import MessageLike
from telethon.tl.types import Message

from packages.models.TelegramMessage import TelegramMessage
from packages.models import Base, encrypt_type_searchable

from packages.bot_assistant import BotAssistant

import sqlalchemy_utils

from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

from urllib.parse import urlparse

import nest_asyncio

import pickle

import asyncio
from asyncio.tasks import Task

from packages.helpers import format_default_message_text

async def add_event_handlers(client : TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Coroutine[TelegramMessage, TelegramClient, Any]):
    new_message_event = events.NewMessage(incoming=True, outgoing=bool(os.getenv('NOTIFY_OUTGOING_MESSAGES', 'True')))
    client.add_event_handler(get_on_new_message(sqlalchemy_session_maker=sqlalchemy_session_maker, client=client), new_message_event)
    client.add_event_handler(get_on_message_deleted(client=client, sqlalchemy_session_maker=sqlalchemy_session_maker, notify_message_deletion=notify_message_deletion), events.MessageDeleted())

def get_on_message_deleted(client: TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Coroutine[TelegramMessage, TelegramClient, Any]):

    async def on_message_deleted(event: MessageDeleted.Event):

        with sqlalchemy_session_maker() as sqlalchemy_session:
            messages = load_messages_from_event(event, sqlalchemy_session)
            sqlalchemy_session.commit()
        
        logging.info(
            "Got {deleted_messages_count} deleted messages. Has in DB {db_messages_count}.".format(
                deleted_messages_count=str(len(event.deleted_ids)),
                db_messages_count=str(len(messages)),
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
        # Cache Lib (Telethon bad)
        await event.get_sender()
        await event.get_input_sender()
        await event.get_chat()
        await event.get_input_chat()
        with sqlalchemy_session_maker() as sqlalchemy_session:
            message : telethon.tl.custom.message.Message = event.message
            orm_message = TelegramMessage(
                id = message.id,
                from_id = (await client.get_entity(message.from_id)).id if message.from_id else None,
                peer_id = (await client.get_entity(message.peer_id)).id if message.peer_id else None,
                text = message.message,
                media = message.media,
                timestamp = message.date
            )
            sqlalchemy_session.add(orm_message)
            sqlalchemy_session.commit()
    return on_new_message

def load_messages_from_event(event: MessageDeleted.Event, sqlalchemy_session : Session) -> List[TelegramMessage]:
    logging.debug(f"Searching for messages in {event.deleted_ids}")
    db_results = sqlalchemy_session.execute(
        select(TelegramMessage)
            .where(TelegramMessage.id.in_(event.deleted_ids))
            # TODO: Filter by chat peer as well because message IDs can duplicate accross chats
            # .where(TelegramMessage.peer_id == event.chat_peer)
    ).scalars().all()
    return db_results

async def clean_old_messages_loop(sqlalchemy_session_maker : sessionmaker, seconds_interval : int, ttl : timedelta):
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
        await asyncio.sleep(seconds_interval)

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

async def main():

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
        return True
    def white_predicate(col : Column):
        return col.name.endswith('_id') or col.name in ['id', 'phone', ]
    for table in metadata.tables.values():
        for column in table.columns:
            logging.debug(f"Traversing Type: {column.type}")
            if not isinstance(column.type, black) and (isinstance(column.type, white) or white_predicate(column)) and final_predicate(column):
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
            int(target_chat) if bool(os.getenv("TARGET_CHAT_IS_ID")) else target_chat,
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
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=str((CONF_DIR / 'server.pem').resolve()), server_side=True)
            while not await client.is_user_authorized():
                logging.info(f"To continue, send GET request to following URL: https://{host}:{port}?code=<code here>&password=<2fa pass if enabled>")
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
            ttl=timedelta(days=int(os.getenv('MESSAGES_TTL_DAYS', 14)))
        )

if __name__ == "__main__":
    asyncio.run(main())

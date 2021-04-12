#!/usr/bin/env python

from asyncio.tasks import Task
import logging
import os
import pathlib
import asyncio
import sqlalchemy

from alchemysession import AlchemySessionContainer
from sqlalchemy.engine.base import Engine
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

from packages.helpers import load_env, require_env, get_mention_username

from packages.models.TelegramMessage import TelegramMessage
from packages.models import Base

from packages.bot_assistant import BotAssistant

from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

from urllib.parse import urlparse

import nest_asyncio

import pickle

CLEAN_OLD_MESSAGES_SECONDS_INTERVAL = 60

async def add_event_handlers(client : TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Coroutine[TelegramMessage, str, Any]):
    new_message_event = events.NewMessage(incoming=True, outgoing=bool(os.getenv('NOTIFY_OUTGOING_MESSAGES', 'True')))
    client.add_event_handler(get_on_new_message(sqlalchemy_session_maker=sqlalchemy_session_maker, client=client), new_message_event)
    client.add_event_handler(get_on_message_deleted(client=client, sqlalchemy_session_maker=sqlalchemy_session_maker, notify_message_deletion=notify_message_deletion), events.MessageDeleted())

def get_on_message_deleted(client: TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Coroutine[TelegramMessage, str, Any]):

    async def on_message_deleted(event: MessageDeleted.Event):

        with sqlalchemy_session_maker() as sqlalchemy_session:
            messages = load_messages_from_event(event, sqlalchemy_session)
            sqlalchemy_session.commit()

        log_deleted_usernames = []

        proms : List[Task[Message]] = []

        for message in messages:
            user = await client.get_entity(message.from_id) if message.from_id else None
            safe_userid = (str(user.id) if user else "0")
            mention_username = await get_mention_username(user)

            log_deleted_usernames.append(mention_username + " (" + safe_userid + ")")
            text = "**Deleted message from: **[{username}](tg://user?id={id})\n".format(username=mention_username, id=safe_userid)
            if message.text:
                text += "**Message:** " + message.text

            proms.append(asyncio.create_task(notify_message_deletion(message, text)))

        logging.info(
            "Got {deleted_messages_count} deleted messages. Has in DB {db_messages_count}. Users: {users}".format(
                deleted_messages_count=str(len(event.deleted_ids)),
                db_messages_count=str(len(messages)),
                users=", ".join(log_deleted_usernames))
        )

        if proms:
            await asyncio.wait(proms)

    return on_message_deleted

def get_on_new_message(sqlalchemy_session_maker : sessionmaker, client : TelegramClient):
    async def on_new_message(event: NewMessage.Event):
        with sqlalchemy_session_maker() as sqlalchemy_session:
            message : telethon.tl.custom.message.Message = event.message
            orm_message = TelegramMessage(
                id = message.id,
                from_id = (await client.get_entity(message.from_id)).id if message.from_id else None,
                text = message.message,
                media = pickle.dumps(message.media),
                timestamp = message.date
            )
            sqlalchemy_session.add(orm_message)
            sqlalchemy_session.commit()
    return on_new_message

def load_messages_from_event(event: MessageDeleted.Event, sqlalchemy_session : Session) -> List[TelegramMessage]:
    logging.debug(f"Searching for messages in {event.deleted_ids}")
    db_results = sqlalchemy_session.execute(
        select(TelegramMessage).where(TelegramMessage.id.in_(event.deleted_ids))
    ).scalars().all()
    return db_results

async def clean_old_messages_loop(sqlalchemy_session_maker : sessionmaker):
    logging.info('Starting Clean Old Messages Loop')
    messages_ttl_days = int(os.getenv('MESSAGES_TTL_DAYS', 14))
    while True:
        delete_from_time = datetime.now(tz=timezone.utc) - timedelta(days=messages_ttl_days)
        with sqlalchemy_session_maker() as sqlalchemy_session:
            res = sqlalchemy_session.execute(
                delete(TelegramMessage).where(TelegramMessage.timestamp < delete_from_time)
            )
            sqlalchemy_session.commit()
            count = res.rowcount
        logging.info(
            f"Deleted {str(count)} messages older than {str(delete_from_time)} from DB"
        )
        await asyncio.sleep(CLEAN_OLD_MESSAGES_SECONDS_INTERVAL)

def get_default_notify_message_deletion(client : TelegramClient):
    async def default_notify_message_deletion(message : TelegramMessage, info : str):
        # TODO: Store in database, flip a flag or something
        logging.info("default_notify_message_deletion")
        await client.send_message("me", message=info, file=pickle.loads(message.media))
    return default_notify_message_deletion

async def main():

    BASE_DIR = pathlib.Path(__file__).parent.absolute().resolve()

    CONF_DIR = (BASE_DIR / '..' / 'conf').absolute().resolve()

    load_env(CONF_DIR)

    logging.basicConfig(level=os.getenv("LOGGING_LEVEL", logging.INFO))

    old_sqlalchemy_engine = sqlalchemy.create_engine(require_env("DATABASE_URL"), echo=True, future=False)
    alchemy_telegram_container = AlchemySessionContainer(engine = old_sqlalchemy_engine, table_base=Base, manage_tables=False, table_prefix=os.getenv("SESSION_TABLE_PREFIX", 'thon_'))

    sqlalchemy_engine = sqlalchemy.create_engine(require_env("DATABASE_URL"), echo=True, future=True)
    sqlalchemy_session_maker = sessionmaker(bind=sqlalchemy_engine, future=True, expire_on_commit=False)

    Base.metadata.create_all(sqlalchemy_engine)

    telegram_api_id = require_env("TELEGRAM_API_ID")
    telegram_api_hash = require_env("TELEGRAM_API_HASH")
    
    target_chat = os.getenv("TARGET_CHAT", "me")
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")

    notify_message_deletion = None
    if telegram_bot_token is not None:
        if target_chat is None or target_chat == "me":
            print('Must provide TARGET_CHAT (except "me") if you want to use bot assistant!')
            exit(1)
        print('Using bot for message notification')
        bot = BotAssistant(target_chat, telegram_api_id, telegram_api_hash, telegram_bot_token)
        notify_message_deletion = bot.notify_message_deletion

    telegram_session = alchemy_telegram_container.new_session(require_env("SESSION_ID"))

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
            expecting_2fa = False
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
                    self.expecting_2fa = False
                    self.send_response(403)
                    self.end_headers()
                except SessionPasswordNeededError:
                    self.expecting_2fa = True
                    self.send_response(401)
                    self.end_headers()
        port = int(require_env("PORT"))
        with HTTPServer(('0.0.0.0', port), MyHandler) as httpd:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=str((CONF_DIR / 'server.pem').resolve()), server_side=True)
            while not await client.is_user_authorized():
                logging.info(f"To continue, send GET request to following URL: https://<host>:{port}?code=<code here>&password=<2fa pass if enabled>")
                httpd.handle_request()

    logging.info('Before With Client')
    async with client:
        logging.info('Inside With Client')
        if not notify_message_deletion:
            notify_message_deletion = get_default_notify_message_deletion(client=client)
        logging.info('Adding event handlers')
        await add_event_handlers(client, sqlalchemy_session_maker, notify_message_deletion)
        logging.info('Added event handlers')
        await clean_old_messages_loop(sqlalchemy_session_maker)

if __name__ == "__main__":
    asyncio.run(main())
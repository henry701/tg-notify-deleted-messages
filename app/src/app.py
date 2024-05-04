#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

import json

logger = logging.getLogger('tgdel-app')

import functools
import os
import signal
import threading
import concurrent
import time

from tenacity import retry, retry_if_exception_type, stop_after_attempt, retry_if_result

import flask

from sqlalchemy.sql.selectable import Select
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError
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

messages_ttl_delta=timedelta(days=int(os.getenv('MESSAGES_TTL_DAYS', 14)))

async def add_event_handlers(client : TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Callable[[TelegramMessage, TelegramClient], Awaitable[Any]], notify_unknown_message : Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]):
    logger.info('Adding event handlers')
    new_message_event = events.NewMessage(incoming=True, outgoing=True)
    client.add_event_handler(get_on_new_message(sqlalchemy_session_maker=sqlalchemy_session_maker, client=client), new_message_event)
    client.add_event_handler(get_on_message_deleted(client=client, sqlalchemy_session_maker=sqlalchemy_session_maker, notify_message_deletion=notify_message_deletion, notify_unknown_message=notify_unknown_message), events.MessageDeleted())
    logger.info('Added event handlers')

def get_on_message_deleted(client: TelegramClient, sqlalchemy_session_maker : sessionmaker, notify_message_deletion : Callable[[TelegramMessage, TelegramClient], Awaitable[Any]], notify_unknown_message : Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]):

    ignore_channels = bool(strtobool(os.getenv("IGNORE_CHANNELS", '0')))
    ignore_groups = bool(strtobool(os.getenv("IGNORE_GROUPS", '0')))
    ignore_megagroups = bool(strtobool(os.getenv("IGNORE_MEGAGROUPS", '0')))
    ignore_gigagroups = bool(strtobool(os.getenv("IGNORE_GIGAGROUPS", '0')))
    member_ignore_threshold = int(os.getenv("MEMBER_IGNORE_THRESHOLD", '0'))
    should_notify_outgoing_messages=bool(strtobool(os.getenv('NOTIFY_OUTGOING_MESSAGES', 'True')))
    deleted_messages_notification_concurrency=int(os.getenv("DELETED_MESSAGES_NOTIFICATION_CONCURRENCY", '1'))

    @retry(retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)), stop=stop_after_attempt(3))
    async def on_message_deleted(event: MessageDeleted.Event):

        deleted_messages_count = len(event.deleted_ids)

        if deleted_messages_count == 0:
            logger.debug("Got empty deleted message event. Returning early!")
            return

        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            (messages, query, unloaded_ids, filtered_away_ids) = await load_messages_from_deleted_event(
                event,
                client,
                sqlalchemy_session,
                ignore_channels,
                ignore_groups,
                ignore_megagroups,
                ignore_gigagroups,
                member_ignore_threshold,
                should_notify_outgoing_messages
        )
        
        deleted_messages_count_str = str(deleted_messages_count)

        db_messages_count = len(messages)
        db_messages_count_str = str(db_messages_count)

        filtered_away_messages_count = len(filtered_away_ids)
        filtered_away_messages_count_str = str(filtered_away_messages_count)
        
        logger.info(
            "Got {deleted_messages_count} deleted messages. Has matching in DB: {db_messages_count}. Filtered away: {filtered_away_messages_count}".format(
                deleted_messages_count=deleted_messages_count_str,
                db_messages_count=db_messages_count_str,
                filtered_away_messages_count=filtered_away_messages_count_str,
            )
        )

        if deleted_messages_count > db_messages_count + filtered_away_messages_count:
            try:
                logger.warning(
                    "Got {deleted_messages_count} deleted messages but only found {db_messages_count} (with {filtered_away_messages_count} filtered away) matching in database! Query: {query_str}".format(
                        deleted_messages_count=deleted_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        filtered_away_messages_count=filtered_away_messages_count_str,
                        query_str=str(query.compile(compile_kwargs={'literal_binds': True})) if query else "(no query)"
                    )
                )
            except Exception as e:
                logger.error(
                    "Error while logging missing deleted message (has {db_messages_count} of {deleted_messages_count}, with {filtered_away_messages_count} filtered away): {e}".format(
                        deleted_messages_count=deleted_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        filtered_away_messages_count=filtered_away_messages_count_str,
                        e=e
                    ), exc_info=True
                )

        awaitables : List[Awaitable[Any]] = []
        for message in messages:
            awaitables.append(notify_message_deletion(message, client))
        if unloaded_ids and len(unloaded_ids):
            awaitables.append(notify_unknown_message(unloaded_ids, event, client))
        if len(awaitables) > 0:
            await gather_with_concurrency(deleted_messages_notification_concurrency, *awaitables)

    return on_message_deleted

def get_on_new_message(sqlalchemy_session_maker : sessionmaker, client : TelegramClient):
    store_message_if_not_exists = get_store_message_if_not_exists(client, sqlalchemy_session_maker)
    @retry(retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)), stop=stop_after_attempt(3))
    async def on_new_message(event: NewMessage.Event):
        effective_level=logger.getEffectiveLevel()
        if effective_level <= 5:
            logger.log(5, f"on_new_message: {event}")
        else:
            logger.debug("in on_new_message")
        message : telethon.tl.custom.message.Message = event.message
        await store_message_if_not_exists(message)
    return on_new_message

def get_should_ignore_message(client : TelegramClient):
    should_ignore_message_chat = get_should_ignore_message_chat(client)
    # We currently only have chat-based message checks, so just delegate here
    async def should_ignore_message(message : telethon.tl.custom.message.Message, check_chat : bool = True) -> bool:
        if not check_chat:
            return False
        return await should_ignore_message_chat(await message.get_chat())
    return should_ignore_message

def get_should_ignore_message_chat(client : TelegramClient):
    ignore_channels = bool(strtobool(os.getenv("IGNORE_CHANNELS", '0')))
    ignore_groups = bool(strtobool(os.getenv("IGNORE_GROUPS", '0')))
    ignore_megagroups = bool(strtobool(os.getenv("IGNORE_MEGAGROUPS", '0')))
    ignore_gigagroups = bool(strtobool(os.getenv("IGNORE_GIGAGROUPS", '0')))
    member_ignore_threshold = int(os.getenv("MEMBER_IGNORE_THRESHOLD", '0'))
    async def should_ignore_message_chat(chat : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None]) -> bool:
        return await raw_should_ignore_message_chat(
            chat,
            client,
            ignore_channels,
            ignore_groups,
            ignore_megagroups,
            ignore_gigagroups,
            member_ignore_threshold
        )
    return should_ignore_message_chat

# https://docs.telethon.dev/en/stable/concepts/chats-vs-channels.html
# https://core.telegram.org/constructor/channel
async def raw_should_ignore_message_chat(
        peer_entity : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None],
        client : TelegramClient,
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
        member_ignore_threshold : int,
    ) -> bool:
    if peer_entity is None:
        return False
    if ignore_channels:
        if isinstance(peer_entity, telethon.types.Channel) and peer_entity.broadcast:
            return True
        # Discussion group for a channel... We should count it as a channel for our purposes
        # https://core.telegram.org/api/discussion
        if isinstance(peer_entity, telethon.types.Channel) and not getattr(peer_entity, 'join_to_send', True):
            return True
        # TODO: Also we want to ignore messages where join_to_send is true, how to know if a group is a discussion group
        # TODO: [...] Without iterating all channels? God damnit, Telegram.
    if ignore_groups:
        if isinstance(peer_entity, telethon.types.Chat):
            return True
    if ignore_megagroups:
        if isinstance(peer_entity, telethon.types.Channel) and peer_entity.megagroup and not peer_entity.gigagroup:
            return True
    if ignore_gigagroups:
        if isinstance(peer_entity, telethon.types.Channel) and peer_entity.gigagroup:
            return True
    if member_ignore_threshold and member_ignore_threshold > 0:
        participants_count : Union[int, None] = None
        if isinstance(peer_entity, telethon.types.Channel):
            input_entity = await client.get_input_entity(peer_entity)
            input_channel = telethon.utils.get_input_channel(input_entity)
            request = telethon.tl.functions.channels.GetFullChannelRequest(channel=input_channel)
            channel_full_info = await client(request)
            full_chat : telethon.types.ChannelFull = channel_full_info.full_chat # type: ignore
            participants_count = full_chat.participants_count
        if isinstance(peer_entity, telethon.types.Chat):
            participants_count = peer_entity.participants_count
        if participants_count and participants_count >= member_ignore_threshold:
            return True
    return False


download_semaphore = asyncio.Semaphore(int(os.getenv("MEDIA_DOWNLOADS_CONCURRENCY", '1')))
file_size_threshold = int(os.getenv("MEDIA_FILE_SIZE_THRESHOLD", '0'))
@retry(retry=retry_if_exception_type(IOError), stop=stop_after_attempt(3))
async def get_message_media_blob(message : telethon.tl.custom.message.Message):
    if not message or not message.media or not message.file or not message.file.size or (file_size_threshold > 0 and message.file.size < file_size_threshold):
        return None
    async with download_semaphore:
        return await message.download_media(file=bytes)

def get_store_message(
    sqlalchemy_session_maker : sessionmaker,
    client : TelegramClient
):
    should_ignore_message = get_should_ignore_message(client)
    @retry(retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)), stop=stop_after_attempt(3))
    async def store_message(message : telethon.tl.custom.message.Message, check_chat : bool = True):
        should_ignore : bool = await should_ignore_message(message, check_chat)
        if should_ignore:
            return False
        built_from_peer = await build_telegram_peer(message.from_id, client, sqlalchemy_session_maker)
        built_chat_peer = await build_telegram_peer(message.peer_id, client, sqlalchemy_session_maker)
        blob = await get_message_media_blob(message)
        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            orm_message = TelegramMessage(
                id = message.id,
                from_peer = built_from_peer,
                chat_peer = built_chat_peer,
                text = message.message,
                media = blob,
                timestamp = message.date
            )
            sqlalchemy_session.merge(orm_message)
        return True
    return store_message

async def should_ignore_deleted_message(
        telegram_message : TelegramMessage,
        client : TelegramClient,
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
        member_ignore_threshold : int,
        should_notify_outgoing_messages : bool
    ) -> bool:
    chat_peer_entity : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None] = await build_peer_entity(telegram_message.chat_peer, client)
    should_ignore_message_chat_result = await raw_should_ignore_message_chat(
        chat_peer_entity,
        client,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold
    )
    if should_ignore_message_chat_result:
        return True
    if should_notify_outgoing_messages:
        from_peer_entity = await build_peer_entity(telegram_message.from_peer, client)
        my_user_peer_entity = await client.get_input_entity('me')
        if from_peer_entity == my_user_peer_entity:
            return True
    return False

async def build_peer_entity(peer : TelegramPeer, client : TelegramClient):
    if peer is None:
        return None
    input_peer = to_telethon_input_peer(peer)
    if input_peer is None:
        return None
    return await client.get_entity(input_peer) # type: ignore

async def load_messages_from_deleted_event(
        event: MessageDeleted.Event,
        client : TelegramClient,
        sqlalchemy_session : Session,
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
        member_ignore_threshold : int,
        should_notify_outgoing_messages : bool
    ) -> Tuple[List[TelegramMessage], Union[Select, None], List[int], List[int]]:
    
    logger.debug(f"Searching for messages in {event.deleted_ids}")

    chat = None
    try:
        input_chat = await event.get_input_chat()
        chat = await client.get_entity(input_chat) if input_chat else None
    except ValueError:
        pass

    return await load_messages_by_parameters(
        event.deleted_ids,
        chat,
        client,
        sqlalchemy_session,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold,
        should_notify_outgoing_messages
    )

async def load_messages_from_db(
    ids : List[int],
    peer_entity : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None],
    sqlalchemy_session : Session,
):
    the_query = select(TelegramMessage).where(TelegramMessage.id.in_(ids))
    peer_entity_id = peer_entity.id if peer_entity is not None else None
    if peer_entity_id is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.peer_id == peer_entity_id))
    chat_peer_type = PeerType.from_type(type(peer_entity))
    if chat_peer_type is not None:
        the_query = the_query.where(TelegramMessage.chat_peer.has(TelegramPeer.type == chat_peer_type))
    db_results : List[TelegramMessage] = list(sqlalchemy_session.execute(the_query).scalars().all())
    loaded_ids = [int(str(message.id)) for message in db_results]
    unloaded_ids = [msg_id for msg_id in ids if msg_id not in loaded_ids]
    return (the_query, db_results, unloaded_ids)

async def load_messages_by_parameters(
    ids : List[int],
    peer_entity : Union[telethon.types.User, telethon.types.Chat, telethon.types.Channel, None],
    client : TelegramClient,
    sqlalchemy_session : Session,
    ignore_channels : bool,
    ignore_groups : bool,
    ignore_megagroups : bool,
    ignore_gigagroups : bool,
    member_ignore_threshold : int,
    should_load_outgoing_messages : bool
):
    # If we know the chat where the event came from,
    # and it should be ignored, then don't even bother
    # querying the database.
    if peer_entity and await raw_should_ignore_message_chat(
        peer_entity,
        client,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold
    ):
        return ([], None, [], ids)

    (the_query, db_results, unloaded_ids) = await load_messages_from_db(
        ids,
        peer_entity,
        sqlalchemy_session,
    )

    filtered_results = await filter_loaded_messages(
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold,
        should_load_outgoing_messages,
        client,
        db_results
    )
    filtered_away_ids = [int(str(message.id)) for message in db_results if message not in filtered_results]

    return (filtered_results, the_query, unloaded_ids, filtered_away_ids)

async def filter_loaded_messages(
        ignore_channels : bool,
        ignore_groups : bool,
        ignore_megagroups : bool,
        ignore_gigagroups : bool,
        member_ignore_threshold : int,
        should_notify_outgoing_messages: bool,
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
            ignore_gigagroups,
            member_ignore_threshold,
            should_notify_outgoing_messages
        )
    ]

async def clean_old_messages_loop(sqlalchemy_session_maker : sessionmaker, seconds_interval : int, ttl : timedelta, stop_event : asyncio.Event):
    logger.info('Starting Clean Old Messages Loop')
    try:
        while True:
            try:
                delete_from_time = datetime.now(tz=timezone.utc) - ttl
                with sqlalchemy_session_maker.begin() as sqlalchemy_session:
                    res = sqlalchemy_session.execute(
                        delete(TelegramMessage).where(TelegramMessage.timestamp < delete_from_time)
                    )
                count = res.rowcount
                logger.info(
                    f"Deleted {str(count)} messages older than {str(delete_from_time)} from DB. Sleeping for {seconds_interval} seconds..."
                )
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop_event.wait(), seconds_interval)
                if stop_event.is_set():
                    logger.info('Stop event is set, breaking from Clean Old Messages Inner Loop!')
                    break
            except Exception as e:
                logger.critical("Error on Clean Old Messages Inner Loop Handler! {e}".format(e=e))
    except Exception as e:
        logger.critical("Error on Clean Old Messages Outer Loop Handler! {e}".format(e=e))
    finally:
        logger.info('Exiting Clean Old Messages Loop')

def get_base_notify_message_deletion(sqlalchemy_session_maker : sessionmaker) -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def base_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
        logger.debug("in base_notify_message_deletion")
        with sqlalchemy_session_maker.begin() as session:
                session.merge(message)
                message.deleted = True # type: ignore
    return base_notify_message_deletion

def get_default_notify_message_deletion() -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def default_notify_message_deletion(message : TelegramMessage, client: TelegramClient):
        logger.debug("in default_notify_message_deletion")
        await client.send_message(
            entity="me",
            message=await format_default_message_text(client, message), # type: ignore
            file=message.media # type: ignore
        )
    return default_notify_message_deletion

def get_default_notify_unknown_message() -> Callable[[List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]]:
    async def default_notify_unknown_message(message_ids : List[int], event : MessageDeleted.Event, client: TelegramClient):
        logger.debug("in default_notify_unknown_message")
        await client.send_message(
            entity="me",
            message=await format_default_unknown_message_text(client, message_ids, event)  # type: ignore
        )
    return default_notify_unknown_message

is_exiting = False
def ask_exit(signame : Union[str, None], loop : asyncio.AbstractEventLoop, additional):
    if signame:
        logger.warning("[exit] Got signal %s: exiting!" % signame)
    else:
        logger.info("[exit] Gracefully exiting, called from code!")
    global is_exiting
    if is_exiting:
        logger.info("ask_exit re-entry detected, ignoring")
        return
    is_exiting = True
    if additional:
        logger.info("[exit] Running user-provided cleanupper")
        try:
            loop.run_until_complete(additional())
        except RuntimeError as e:
            if "Event loop stopped before Future completed" not in str(e):
                logger.error("[exit] Error while running user-provided cleanupper", exc_info=True)
        else:
            logger.info("[exit] Successfully ran user-provided cleanupper")
    all_tasks = asyncio.all_tasks(loop)
    tasklen = len(all_tasks)
    if tasklen > 0:
        logger.warning("[exit] Cancelling all remaining {tasklen} asyncio tasks!".format(tasklen=tasklen))
        for task in all_tasks:
            task.cancel()
        logger.warning("[exit] Cancelled all remaining {tasklen} asyncio tasks!".format(tasklen=tasklen))
    logger.info("[exit] Stopping the loop!")
    loop.stop()
    logger.info("[exit] Bye bye! Gracefully exited.")

async def make_client(alchemy_telegram_container : AlchemySessionContainer, telegram_api_id, telegram_api_hash, session_id, loop : asyncio.AbstractEventLoop):
    
    def construct_client():
        return TelegramClient(
            session=telegram_session,
            api_id=telegram_api_id,
            api_hash=telegram_api_hash,
            loop=loop,
            flood_sleep_threshold=65500,
            request_retries=50,
            connection_retries=None,
            entity_cache_limit=1000,
            use_ipv6=bool(strtobool(os.getenv("USE_IPV6", '0'))),
        )
    
    telegram_session = alchemy_telegram_container.new_session(session_id)
    client = construct_client()
    logger.info('Connecting Telegram Client')
    try:
        await client.connect()
    except AuthKeyDuplicatedError:
        logger.error('AuthKeyDuplicatedError, disconnecting telegram client and re-creating session!', exc_info=True)
        telegram_session.delete()
        telegram_session = alchemy_telegram_container.new_session(session_id)
        client = construct_client()
        logger.info('Connecting Telegram Client again')
        await client.connect()
    logger.info('Telegram Client Connected!')
    return client

def add_signal_handlers(loop, closer):
    for signame in {'SIGINT', 'SIGTERM'}:
        loop.add_signal_handler(
            getattr(signal, signame),
            functools.partial(ask_exit, signame, loop, closer)
        )

async def configure_bot(alchemy_telegram_container, telegram_api_id, telegram_api_hash, target_chat, session_id):
    logger.info('Configuring Bot')
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    configured_notify_message_deletion = None
    configured_notify_unknown_message = None
    bot = None
    if telegram_bot_token is not None:
        if target_chat is None or target_chat == "me":
            logger.critical('Must provide TARGET_CHAT (except "me") if you want to use bot assistant!')
            os._exit(1)
        logger.info('Using bot for message notification')
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
    logger.info('Configured Bot')
    return configured_notify_message_deletion,configured_notify_unknown_message,bot

async def client_main_loop_job(stop_event : asyncio.Event, started_event : asyncio.Event, sqlalchemy_session_maker : sessionmaker, configured_notify_message_deletion, configured_notify_unknown_message, client : TelegramClient):
    if not configured_notify_message_deletion:
        configured_notify_message_deletion = get_default_notify_message_deletion()
    if not configured_notify_unknown_message:
        configured_notify_unknown_message = get_default_notify_unknown_message()
    base_notify_message_deletion = get_base_notify_message_deletion(sqlalchemy_session_maker=sqlalchemy_session_maker)
    async def actual_notify_message_deletion(message : TelegramMessage, client : TelegramClient):
        await base_notify_message_deletion(message, client)
        await configured_notify_message_deletion(message, client)
    add_event_handlers_task = asyncio.create_task(add_event_handlers(client, sqlalchemy_session_maker, actual_notify_message_deletion, configured_notify_unknown_message))
    preload_messages_task = asyncio.create_task(preload_messages(client, sqlalchemy_session_maker))
    old_messages_clean_loop_task = asyncio.create_task(clean_old_messages_loop(
        sqlalchemy_session_maker=sqlalchemy_session_maker,
        seconds_interval=int(os.getenv("CLEAN_OLD_MESSAGES_SECONDS_INTERVAL", 900)),
        ttl=messages_ttl_delta,
        stop_event=stop_event
    ))
    stop_event_task = asyncio.create_task(stop_event.wait())
    def on_stop(fut):
        add_event_handlers_task.cancel()
        preload_messages_task.cancel()
    stop_event_task.add_done_callback(on_stop)
    await asyncio.gather(add_event_handlers_task, preload_messages_task)
    started_event.set()
    await old_messages_clean_loop_task
    await stop_event_task

def create_app_and_start_jobs() -> Tuple[flask.Flask, Callable[[], None]]:

    loop : asyncio.AbstractEventLoop = asyncio.events.new_event_loop()
    nest_asyncio.apply(loop)

    stop_event : Union[asyncio.Event, None] = None
    client : Union[TelegramClient, None] = None
    bot : Union[BotAssistant, None] = None

    closer_called = False
    async def closer():
        nonlocal stop_event
        nonlocal client
        nonlocal bot
        nonlocal closer_called
        close_coros = []
        logger.info("Inside closer()")
        if closer_called:
            logger.info("Closer re-entry detected, ignoring")
            return
        closer_called = True
        if stop_event is not None:
            logger.info("Setting stop event flag")
            stop_event.set()
        if client is not None:
            logger.info("Disconnecting Client")
            disconnecter_coro = client.disconnect()
            if disconnecter_coro is not None:
                close_coros.append(disconnecter_coro)
            client = None
        if bot is not None:
            logger.info("Disconnecting Bot")
            close_coros.append(bot.__aexit__(None, None, None))
        try:
            await asyncio.gather(*close_coros)
        except Exception as e:
            logger.critical("Error while running closer coroutines!", exc_info=True)
            os._exit(1)
    
    def sync_closer():
        ask_exit(None, loop, closer)

    add_signal_handlers(loop, closer)

    database_url = get_db_url()

    sqlalchemy_engine = create_engine(database_url, True)
    sqlalchemy_session_maker = sessionmaker(bind=sqlalchemy_engine, future=True, expire_on_commit=False)

    old_sqlalchemy_engine = create_engine(database_url, False, sqlalchemy_engine.pool)
    alchemy_telegram_container = AlchemySessionContainer(engine = old_sqlalchemy_engine, table_base=Base, manage_tables=False, table_prefix=os.getenv("SESSION_TABLE_PREFIX", 'thon_'))
    alchemy_telegram_container.core_mode = True

    create_database(sqlalchemy_engine)

    telegram_api_id = require_env("TELEGRAM_API_ID")
    telegram_api_hash = require_env("TELEGRAM_API_HASH")

    target_chat = os.getenv("TARGET_CHAT", "me")

    session_id = require_env("SESSION_ID")

    configured_notify_message_deletion, configured_notify_unknown_message, bot = loop.run_until_complete(configure_bot(alchemy_telegram_container, telegram_api_id, telegram_api_hash, target_chat, session_id))

    client = loop.run_until_complete(make_client(alchemy_telegram_container, telegram_api_id, telegram_api_hash, session_id, loop))

    started_event : Union[asyncio.Event, None] = None

    def worker_function(loop : asyncio.AbstractEventLoop, sync_closer : Callable[[], Any]):
        logger.info("Entering worker function!")
        try:
            asyncio.set_event_loop(loop)
            nonlocal stop_event
            stop_event = asyncio.Event()
            nonlocal started_event
            started_event = asyncio.Event()
            loop.run_forever()
        except Exception as e:
            logger.critical("Error on worker function! {e}".format(e=e), exc_info=True)
            sync_closer()
            os._exit(1)
        finally:
            logger.info("Exiting worker function!")
        os._exit(0)
    worker_thread = threading.Thread(target=worker_function, args=(loop, sync_closer), name='loop-app-client-bgthread')
    worker_thread.start()

    while (stop_event is None or started_event is None) and worker_thread.is_alive:
        time.sleep(0)

    if (stop_event is None or started_event is None):
        raise RuntimeError("Worker thread died before setting stop_event and start_event!")

    main_loop_job_future = asyncio.run_coroutine_threadsafe(
        client_main_loop_job(stop_event, started_event, sqlalchemy_session_maker, configured_notify_message_deletion, configured_notify_unknown_message, client),
        loop
    )

    def handle_main_loop_job_future_end(main_inner_future : concurrent.futures.Future):
        try:
            main_inner_future.result()
        except Exception as e:
            if stop_event.is_set():
                return
            logger.error("Error while running main job: {e}".format(e=e), exc_info=True)
            sync_closer()
            os._exit(1)
        else:
            logger.info("Main job loop finished, calling sync closer")
            sync_closer()

    main_loop_job_future.add_done_callback(handle_main_loop_job_future_end)

    flask_app = create_app(
        client,
        bot,
        loop,
        sqlalchemy_session_maker,
        sync_closer
    )

    logger.info("Returning from create_app_and_start_jobs")
    return (flask_app, sync_closer)

def get_store_message_if_not_exists(client : TelegramClient, sqlalchemy_session_maker : sessionmaker):
    store_message = get_store_message(sqlalchemy_session_maker, client)
    should_ignore_message = get_should_ignore_message(client)
    @retry(retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)), stop=stop_after_attempt(3))
    async def store_message_if_not_exists(message : telethon.tl.custom.message.Message, check_chat : bool = True):
        if await should_ignore_message(message, check_chat):
            return False
        peer_entity = await message.get_chat()
        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            (the_query, messages, unloaded_ids) = await load_messages_from_db(
                [ message.id ],
                peer_entity,
                sqlalchemy_session,
            )
            # Message already exists, ignore
            if len(messages) > 0:
                return False
        return await store_message(message)
    return store_message_if_not_exists

async def preload_messages(client : TelegramClient, sqlalchemy_session_maker : sessionmaker):

    if not bool(strtobool(os.getenv('PRELOAD_MESSAGES', '0'))):
        logger.info('PRELOAD_MESSAGES is disabled, skipping preloading messages')
        return
    
    if not client.is_connected or not await client.is_user_authorized():
        logger.info('No client connected and authorized, skipping preloading messages')
        return
    
    iter_from_offset=datetime.now(tz=timezone.utc) - messages_ttl_delta
    logger.info('Preloading existing messages from {iter_from_offset}'.format(iter_from_offset=iter_from_offset))

    iterated_messages=0
    preloaded_messages=0

    preload_status_report_interval=int(os.getenv("PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL", '60'))
    async def preload_messages_status_loop():
        if preload_status_report_interval <= 0:
            return
        while True:
            try:
                await asyncio.sleep(preload_status_report_interval)
            except asyncio.CancelledError:
                return
            logger.info('Preloading still in progress. Total so far: {preloaded_messages} preloaded, {iterated_messages} iterated'.format(preloaded_messages=preloaded_messages, iterated_messages=iterated_messages))

    preload_messages_status_task = asyncio.create_task(preload_messages_status_loop())

    store_message_if_not_exists = get_store_message_if_not_exists(client, sqlalchemy_session_maker)
    should_ignore_message_chat = get_should_ignore_message_chat(client)

    async def preload_messages_for_dialog(dialog):

        logger.debug('Preloading existing messages for dialog={dialog}'.format(dialog=dialog.id))

        peer = dialog.input_entity
        full_peer = await client.get_entity(peer)

        if await should_ignore_message_chat(full_peer):
            logger.debug('Preloading ignoring filtered dialog={dialog}'.format(dialog=dialog.id))
            return

        iterated_messages_this_dialog=0
        preloaded_messages_this_dialog=0

        message : telethon.tl.custom.message.Message = None
        async for message in client.iter_messages(full_peer, offset_date=iter_from_offset, reverse=True):
            nonlocal iterated_messages
            nonlocal preloaded_messages
            iterated_messages = iterated_messages + 1
            iterated_messages_this_dialog = iterated_messages_this_dialog + 1
            # Already checked chat for ignore, don't re-check ignore logic.
            message_result = await store_message_if_not_exists(message, False)
            if message_result is False:
                continue
            preloaded_messages = preloaded_messages + 1
            preloaded_messages_this_dialog = preloaded_messages_this_dialog + 1

        logger.debug('Preloaded {preloaded_messages_this_dialog} existing messages for dialog={dialog}'.format(dialog=dialog.id, preloaded_messages_this_dialog=preloaded_messages_this_dialog))
        
    dialog_coros = []
    dialog : telethon.tl.custom.dialog.Dialog = None
    async for dialog in client.iter_dialogs():
        dialog_coros.append(preload_messages_for_dialog(dialog))
    if len(dialog_coros) > 0:
        await gather_with_concurrency(int(os.getenv("PRELOAD_MESSAGES_DIALOG_CONCURRENCY", '8')), *dialog_coros)

    preload_messages_status_task.cancel()
    logger.info('Preloading finished! Existing message preloaded count: {preloaded_messages}. Total messages iterated: {iterated_messages}'.format(preloaded_messages=preloaded_messages, iterated_messages=iterated_messages))

async def gather_with_concurrency(n, *coros):
    semaphore = asyncio.Semaphore(n)
    async def sem_coro(coro):
        async with semaphore:
            return await coro
    return await asyncio.gather(*(sem_coro(c) for c in coros))

def create_engine(database_url : str, future : bool, pool : Union[sqlalchemy.pool.Pool, None] = None):
    if pool is not None:
        logger.debug("Reusing Pool")
        return sqlalchemy.create_engine(
            database_url,
            echo=False,
            future=future, # type: ignore
            pool=pool,
        )
    connect_args = json.loads(os.getenv('CUSTOM_SQLALCHEMY_CONNECT_ARGS')) if os.getenv('CUSTOM_SQLALCHEMY_CONNECT_ARGS') else {}
    create_engine_add_args = json.loads(os.getenv('CUSTOM_SQLALCHEMY_CREATE_ENGINE_ARGS')) if os.getenv('CUSTOM_SQLALCHEMY_CREATE_ENGINE_ARGS') else {}
    return sqlalchemy.create_engine(
        database_url,
        echo=False,
        future=future, # type: ignore
        connect_args=connect_args,
        **create_engine_add_args
    )

def create_app(client : Union[TelegramClient, None], bot : Union[BotAssistant, None], loop : asyncio.AbstractEventLoop, sqlalchemy_session_maker : sessionmaker, sync_closer) -> flask.Flask:

    if client is None:
        raise ValueError('Client not initialized!')

    flask_app = flask.Flask(__name__)

    phone = require_env("PHONE_NUMBER")

    sent_code : Union[telethon.types.auth.SentCode, None] = None

    add_informative_routes(client, bot, flask_app, loop, sqlalchemy_session_maker)

    bearer_token = os.getenv("HTTP_BEARER_TOKEN")

    @flask_app.before_request
    def before_request():
        if bearer_token is None:
            return
        auth_header_value = flask.request.headers.get("Authorization")
        if auth_header_value != "Bearer {token}".format(token=bearer_token):
            return flask.Response(status=401)

    @flask_app.route('/send_code', methods=['GET'])
    def send_code():
        logger.info('Sending code request')
        nonlocal sent_code
        sent_code = asyncio.run_coroutine_threadsafe(client.send_code_request(phone=phone), loop).result()
        logger.info('Sent code request')
        return flask.Response(status=204)

    @flask_app.route('/logout', methods=['GET'])
    def logout():
        logger.info('Logging out')
        asyncio.run_coroutine_threadsafe(client.log_out(), loop).result()
        logger.info('Logged out! Exiting, because client is unusable.')
        loop.call_later(1, sync_closer)
        return flask.Response(status=204)

    @flask_app.route('/auth', methods=['GET'])
    def auth():
        nonlocal sent_code
        logger.info('Auth request received')
        code = flask.request.args.get("code")
        password = flask.request.args.get("password")
        if not sent_code:
            return flask.Response("Missing send_code request", status=401)
        if not code and not password:
            return flask.Response("Missing code and password queryParameter. Either one or the other should be present!", status=403)
        if code and password:
            return flask.Response("Both code and password parameters present, but either one or the other should be present!", status=400)
        try:
            logger.info('Attempting to sign in')
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
                preload_future = asyncio.run_coroutine_threadsafe(preload_messages(client, sqlalchemy_session_maker), loop)
                def handle_preload_result(preload_inner_future : concurrent.futures.Future):
                    try:
                        preload_inner_future.result()
                    except Exception as e:
                        logger.error("Error while preloading after login: {e}".format(e=e), exc_info=True)
                preload_future.add_done_callback(handle_preload_result)
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
    @retry(retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)) | retry_if_result(lambda result: isinstance(result, flask.Response) and str(result.status_code).startswith('5')), stop=stop_after_attempt(3))
    def health():
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
                sqlalchemy_session.execute(
                    select(TelegramMessage).limit(1)
                )
        except Exception as e:
            return log_and_return_500("Database Error on health query: {e}".format(e=e))
        logger.debug("Checking Telegram Client Communication")
        try:
            asyncio.run_coroutine_threadsafe(client.is_user_authorized(), loop).result()
        except Exception as e:
            log_and_return_500("Telegram Error while checking Telegram Client Communication: {e}".format(e=e))
        if bot is not None and bot.client is not None and bot.client.is_connected():
            logger.debug("Checking Telegram Bot Communication")
            try:
                asyncio.run_coroutine_threadsafe(bot.client.is_user_authorized(), loop).result()
            except Exception as e:
                log_and_return_500("Telegram Error while checking Telegram Bot Communication: {e}".format(e=e))
        return flask.Response(status=204)

    def log_and_return_500(message : str):
        logger.error(message, exc_info=True)
        return flask.Response(message, status=500)

def main():
    app, closer = create_app_and_start_jobs()
    port = int(require_env("PORT"))
    app.run(port=port, host='0.0.0.0')
    closer()

if __name__ == "__main__":
    main()

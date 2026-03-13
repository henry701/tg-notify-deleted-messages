# -*- coding: utf-8 -*-

from typing import Any, Awaitable, Callable, List

from sqlalchemy.orm import sessionmaker
from telethon import TelegramClient
from telethon.events.messagedeleted import MessageDeleted

from packages.models.root.TelegramMessage import TelegramMessage
from packages.telegram_helpers import (
    format_default_message_text,
    format_default_unknown_message_text,
)


def get_base_notify_message_deletion(
    sqlalchemy_session_maker: sessionmaker,
) -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def base_notify_message_deletion(
        message: TelegramMessage, client: TelegramClient
    ):
        with sqlalchemy_session_maker.begin() as session:
            session.merge(message)
            message.deleted = True  # type: ignore

    return base_notify_message_deletion


def get_default_notify_message_deletion() -> Callable[
    [TelegramMessage, TelegramClient], Awaitable[Any]
]:
    async def default_notify_message_deletion(
        message: TelegramMessage, client: TelegramClient
    ):
        await client.send_message(
            entity="me",
            message=await format_default_message_text(client, message),  # type: ignore
            file=message.media,  # type: ignore
        )

    return default_notify_message_deletion


def get_default_notify_unknown_message() -> Callable[
    [List[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]
]:
    async def default_notify_unknown_message(
        message_ids: List[int], event: MessageDeleted.Event, client: TelegramClient
    ):
        await client.send_message(
            entity="me",
            message=await format_default_unknown_message_text(
                client, message_ids, event
            ),  # type: ignore
        )

    return default_notify_unknown_message

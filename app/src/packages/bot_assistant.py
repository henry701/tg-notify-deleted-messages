import logging
from collections.abc import Callable

from telethon import TelegramClient, hints
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError
from telethon.events.messagedeleted import MessageDeleted
from telethon.sessions.abstract import Session

from packages.models.root.TelegramMessage import TelegramMessage
from packages.telegram_helpers import (
    format_default_message_batch_texts,
    format_default_message_edit_text,
    format_default_unknown_message_text,
    send_stored_messages_with_optional_media,
    send_stored_message_with_optional_media,
)


class BotAssistant:
    def __init__(
        self,
        target_chat: hints.EntityLike,
        api_id: str | int,
        api_hash: str,
        bot_token: str,
        session_maker: Callable[[], Session],
    ):
        self.target_chat = target_chat
        self.api_id = int(api_id)
        self.api_hash = api_hash
        self.bot_token = bot_token
        self.session_maker = session_maker

    async def __aenter__(self):
        self.session = self.session_maker()
        self.client = TelegramClient(
            session=self.session, api_id=self.api_id, api_hash=self.api_hash
        )
        try:
            await self.client.connect()
            await self.client.sign_in(bot_token=self.bot_token)
        except AuthKeyDuplicatedError:
            self.session.delete()
            self.session = self.session_maker()
            self.client = TelegramClient(
                session=self.session, api_id=self.api_id, api_hash=self.api_hash
            )
            await self.client.connect()
            await self.client.sign_in(bot_token=self.bot_token)

    async def __aexit__(self, *args):
        self.throw_if_uninitialized()
        assert self.client is not None
        await self.client.__aexit__(*args)
        self.client = None

    async def notify_message_deletion(
        self, message: TelegramMessage, client: TelegramClient
    ):
        logging.debug("bot_assistant notify_message_deletion")
        self.throw_if_uninitialized()
        assert self.client is not None
        logging.debug("bot_assistant notify_message_deletion send_message")
        raw_album_messages = getattr(message, "album_messages", None)
        album_messages = (
            raw_album_messages
            if isinstance(raw_album_messages, list) and len(raw_album_messages) > 0
            else [message]
        )
        await send_stored_messages_with_optional_media(
            sender_client=self.client,
            entity=self.target_chat,
            formatted_texts=await format_default_message_batch_texts(
                client, album_messages
            ),
            messages=album_messages,
        )

    async def notify_unknown_message(
        self,
        message_ids: list[int],
        event: MessageDeleted.Event,
        client: TelegramClient,
    ):
        logging.debug("bot_assistant notify_unknown_message")
        self.throw_if_uninitialized()
        assert self.client is not None
        logging.debug("bot_assistant notify_unknown_message send_message")
        await self.client.send_message(
            entity=self.target_chat,
            message=await format_default_unknown_message_text(
                client, message_ids, event
            ),
        )

    async def notify_message_edit(
        self, message: TelegramMessage, client: TelegramClient
    ):
        logging.debug("bot_assistant notify_message_edit")
        self.throw_if_uninitialized()
        assert self.client is not None
        logging.debug("bot_assistant notify_message_edit send_message")
        await send_stored_message_with_optional_media(
            sender_client=self.client,
            entity=self.target_chat,
            formatted_text=await format_default_message_edit_text(client, message),
            message=message,
        )

    def throw_if_uninitialized(self):
        if not self.client:
            raise RuntimeError("Not started!")

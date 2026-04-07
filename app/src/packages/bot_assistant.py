import logging
from collections.abc import Callable

from telethon import TelegramClient, hints
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError
from telethon.events.messagedeleted import MessageDeleted
from telethon.sessions.abstract import Session

from packages.models.root.TelegramMessage import TelegramMessage
from packages.telegram_helpers import (
    format_default_message_text,
    format_default_unknown_message_text,
    get_mention_text,
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
        await self.client.send_message(
            entity=self.target_chat,
            message=await format_default_message_text(client, message),
            file=message.media,
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
        await self.client.send_message(
            entity=self.target_chat,
            message="**Edited message** from: [{}](tg://user?id={}) on chat [{}](tg://chat?id={})\n**New Text:** {}".format(
                (await get_mention_text(client, message.from_peer))
                if message.from_peer
                else "Unknown",
                (str(message.from_peer.id) if message.from_peer else "0"),
                (await get_mention_text(client, message.chat_peer))
                if message.chat_peer
                else "Unknown",
                (str(message.chat_peer.id) if message.chat_peer else "0"),
                message.text or "",
            ),
            file=message.media,
        )

    def throw_if_uninitialized(self):
        if not self.client:
            raise RuntimeError("Not started!")

# -*- coding: utf-8 -*-

import logging
import pickle
from typing import Union
from telethon import TelegramClient, hints
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError
from telethon.sessions.abstract import Session
from packages.helpers import format_default_message_text

from packages.models.root.TelegramMessage import TelegramMessage

class BotAssistant():

    def __init__(self, target_chat : hints.EntityLike, api_id : Union[str, int], api_hash : str, bot_token : str, session : Union[str, Session] = "db/bot_assistant"):
        self.target_chat = target_chat
        self.api_id = int(api_id)
        self.api_hash = api_hash
        self.bot_token = bot_token
        self.session = session

    async def __aenter__(self):
        client = TelegramClient(session=self.session, api_id=self.api_id, api_hash=self.api_hash)
        self.client = client
        try:
            await client.connect()
            await client.sign_in(bot_token=self.bot_token)
        except AuthKeyDuplicatedError:
            self.session.delete()
            await client.connect()
            await client.sign_in(bot_token=self.bot_token)

    async def __aexit__(self, *args):
        if(not self.client):
            raise RuntimeError("Not started!")
        await self.client.__aexit__(*args)
        self.client = None

    async def notify_message_deletion(self, message : TelegramMessage, client: TelegramClient):
        logging.debug("bot_assistant notify_message_deletion")
        if(not self.client):
            raise RuntimeError("Not started!")
        logging.debug("bot_assistant notify_message_deletion send_message")
        await self.client.send_message(
            entity=self.target_chat,
            message=await format_default_message_text(client, message),
            file=message.media
        ) 

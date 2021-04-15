# -*- coding: utf-8 -*-

from typing import Union
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import select
import telethon
from telethon.client.telegramclient import TelegramClient
from telethon.tl.types import InputPeerChannel, InputPeerChat, InputPeerUser, PeerChannel, PeerChat, PeerUser
from packages.models.root.TelegramMessage import TelegramMessage
from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType

async def get_mention_username(user):
    if not user:
        return "Anonymous"
    if user.first_name or user.last_name:
        mention_username = \
            (user.first_name + " " if user.first_name else "") + \
            (user.last_name if user.last_name else "")
    elif user.username:
        mention_username = user.username
    elif user.phone:
        mention_username = user.phone
    else:
        mention_username = user.id
    return mention_username

async def build_telegram_peer(peer : Union[PeerUser, PeerChat, PeerChannel, None], client : TelegramClient, sqlalchemy_session : Session) -> TelegramPeer:
    if peer is None:
        return None
    got_entity = (await client.get_input_entity(peer))
    tele_peer = TelegramPeer(
        peer_id = await client.get_peer_id(peer=got_entity, add_mark=False),
        type = PeerType.from_type(type(got_entity), mandatory=True),
        access_hash = got_entity.access_hash if hasattr(got_entity, 'access_hash') else None,
    )
    return sqlalchemy_session.execute(
        select(TelegramPeer)
            .where(TelegramPeer.peer_id == tele_peer.peer_id)
            .where(TelegramPeer.type == tele_peer.type)
    ).scalar() or tele_peer

def to_telethon_input_peer(telegram_peer : TelegramPeer) -> Union[InputPeerUser, InputPeerChannel, InputPeerChat]:
    return PeerType(telegram_peer.type).to_input_type(telegram_peer.peer_id, telegram_peer.access_hash)

async def refresh_client(client : TelegramClient):
    await client.get_dialogs()
    await client.get_me()
    await client.get_messages(limit=10)

async def format_default_message_text(client : TelegramClient, message : TelegramMessage, tried : bool = False):
    try:
        user = await client.get_entity(to_telethon_input_peer(message.from_peer)) if message.from_peer_id else None
        chat = await client.get_entity(to_telethon_input_peer(message.chat_peer))
    except ValueError:
        if tried:
            raise
        refresh_client(client)
        return format_default_message_text(client=client, message=message, tried=True)
    mention_username = await get_mention_username(user)
    mention_chatname = await get_mention_username(chat)
    text = "**Deleted message from: **[{username}](tg://user?id={userid}) on chat [{chatname}](tg://chat?id={chatid})\n".format(
        username=mention_username,
        userid=(str(user.id) if user else "0"),
        chatname=mention_chatname,
        chatid=(str(chat.id) if chat else "0"),
    )
    if message.text:
        text += "**Message Text:** " + message.text
    return text

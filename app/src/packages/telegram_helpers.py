# -*- coding: utf-8 -*-

from typing import List, Union
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import select
from telethon.client.telegramclient import TelegramClient
from telethon.events.messagedeleted import MessageDeleted
from telethon.tl.types import InputPeerChannel, InputPeerChat, InputPeerUser, PeerChannel, PeerChat, PeerUser
from packages.models.root.TelegramMessage import TelegramMessage
from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType

async def get_mention_text(entity):
    if not entity:
        mention_username = "Anonymous"
    elif getattr(entity, 'title', None):
        mention_username = entity.title
    elif getattr(entity, 'first_name', None) or getattr(entity, 'last_name', None):
        mention_username = \
            (getattr(entity, 'first_name', '') + " " if getattr(entity, 'first_name', '') else '') + \
            (getattr(entity, 'last_name', '') if getattr(entity, 'last_name', '') else '')
    elif getattr(entity, 'username', None):
        mention_username = entity.username
    elif getattr(entity, 'phone', None):
        mention_username = entity.phone
    else:
        mention_username = getattr(entity, 'id', None)
        if not mention_username:
            mention_username = getattr(entity, 'chat_id', None)
    if not mention_username:
        mention_username = "UNKNOWN. Type name: " + type(entity).__name__
    return mention_username

async def build_telegram_peer(peer : Union[PeerUser, PeerChat, PeerChannel, None], client : TelegramClient, sqlalchemy_session : Session) -> Union[TelegramPeer, None]:
    async def find_existing_peer(tele_peer):
        return sqlalchemy_session.execute(
            select(TelegramPeer)
                .where(TelegramPeer.peer_id == tele_peer.peer_id)
                .where(TelegramPeer.type == tele_peer.type)
        ).scalar()
    if peer is None:
        return None
    got_entity = (await client.get_input_entity(peer))
    tele_peer = TelegramPeer(
        peer_id = await client.get_peer_id(peer=got_entity, add_mark=False),
        type = PeerType.from_type(type(got_entity), mandatory=True),
        access_hash = got_entity.access_hash if hasattr(got_entity, 'access_hash') else None,
    )
    existing_peer = await find_existing_peer(tele_peer)
    if existing_peer:
        return existing_peer
    sqlalchemy_session.add(tele_peer)
    sqlalchemy_session.flush()
    return await find_existing_peer(tele_peer)

def to_telethon_input_peer(telegram_peer : TelegramPeer) -> Union[InputPeerUser, InputPeerChannel, InputPeerChat]:
    return PeerType(telegram_peer.type).to_input_type(telegram_peer.peer_id, telegram_peer.access_hash)

async def refresh_client(client : TelegramClient):
    await client.get_dialogs()
    await client.get_me()
    await client.get_messages(limit=10)

async def format_default_message_text(client : TelegramClient, message : TelegramMessage, tried : bool = False):
    try:
        user = await client.get_entity(to_telethon_input_peer(message.from_peer)) if message.from_peer else None
        chat = await client.get_entity(to_telethon_input_peer(message.chat_peer)) if message.chat_peer else None
    except ValueError:
        if tried:
            raise
        await refresh_client(client)
        return format_default_message_text(client=client, message=message, tried=True)
    mention_username = await get_mention_text(user)
    mention_chatname = await get_mention_text(chat)
    text = "**Deleted message** from: [{username}](tg://user?id={userid}) on chat [{chatname}](tg://chat?id={chatid})\n".format(
        username=mention_username,
        userid=(str(user.id) if user else "0"),
        chatname=mention_chatname,
        chatid=(str(chat.id) if chat else "0"),
    )
    if message.text:
        text += "**Message Text:** " + message.text
    return text

async def format_default_unknown_message_text(client : TelegramClient, message_ids : List[int], event : MessageDeleted.Event, tried : bool = False) -> str:
    try:
        input_chat = await event.get_input_chat()
        chat = await client.get_entity(input_chat) if input_chat else None
    except ValueError:
        if tried:
            raise
        await refresh_client(client)
        return await format_default_unknown_message_text(client=client, message_ids=message_ids, event=event, tried=True)
    mention_chatname = await get_mention_text(chat)
    text = "**Unknown deleted messages** on chat [{chatname}](tg://user?id={chatid})\n".format(
        chatname=mention_chatname,
        chatid=(str(chat.id) if chat else "0"),
    )
    text += "**Message IDs (" + str(len(message_ids)) + " total):** " + ', '.join(str(x) for x in message_ids)
    return text

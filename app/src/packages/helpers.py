# -*- coding: utf-8 -*-

from telethon.client.telegramclient import TelegramClient
from packages.models.TelegramMessage import TelegramMessage

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

async def format_default_message_text(client : TelegramClient, message : TelegramMessage):
    user = await client.get_entity(message.from_id) if message.from_id else None
    chat = await client.get_entity(message.peer_id)
    mention_username = await get_mention_username(user)
    mention_chatname = await get_mention_username(chat)
    text = "**Deleted message from: **[{username}](tg://user?id={userid}) on chat [{chatname}](tg://chat?id={chatid})\n".format(
        username=mention_username,
        userid=(str(user.id) if user else "0"),
        chatname=mention_chatname,
        chatid=message.peer_id
    )
    if message.text:
        text += "**Message Text:** " + message.text
    return text

# -*- coding: utf-8 -*-
"""Message filtering logic for determining which messages should be ignored."""

from typing import Union

import telethon
from telethon import TelegramClient

from packages.models.root.TelegramMessage import TelegramMessage


async def raw_should_ignore_message_chat(
    peer_entity: Union[
        telethon.types.User, telethon.types.Chat, telethon.types.Channel, None
    ],
    client: TelegramClient,
    ignore_channels: bool,
    ignore_groups: bool,
    ignore_megagroups: bool,
    ignore_gigagroups: bool,
    member_ignore_threshold: int,
) -> bool:
    """
    Determine if a message from a given peer entity should be ignored based on chat type filters.

    Filtering rules:
    - Channels (broadcast=True) are ignored if ignore_channels is True
    - Discussion groups for channels are treated as channels
    - Regular groups (telethon.types.Chat) are ignored if ignore_groups is True
    - Megagroups are ignored if ignore_megagroups is True
    - Gigagroups are ignored if ignore_gigagroups is True
    - Groups with participant count >= member_ignore_threshold are ignored

    References:
    - https://docs.telethon.dev/en/stable/concepts/chats-vs-channels.html
    - https://core.telegram.org/constructor/channel
    - https://core.telegram.org/api/discussion

    Args:
        peer_entity: The peer entity to check (User, Chat, or Channel)
        client: Telegram client for fetching additional info if needed
        ignore_channels: Whether to ignore channel messages
        ignore_groups: Whether to ignore regular group messages
        ignore_megagroups: Whether to ignore megagroup messages
        ignore_gigagroups: Whether to ignore gigagroup messages
        member_ignore_threshold: Minimum participant count to ignore (0 disables)

    Returns:
        True if messages from this peer should be ignored, False otherwise
    """
    if peer_entity is None:
        return False

    if ignore_channels:
        if isinstance(peer_entity, telethon.types.Channel) and peer_entity.broadcast:
            return True
        # Discussion group for a channel... We should count it as a channel for our purposes
        # https://core.telegram.org/api/discussion
        if isinstance(peer_entity, telethon.types.Channel) and not getattr(
            peer_entity, "join_to_send", True
        ):
            return True

    if ignore_groups:
        if isinstance(peer_entity, telethon.types.Chat):
            return True

    if ignore_megagroups:
        if (
            isinstance(peer_entity, telethon.types.Channel)
            and peer_entity.megagroup
            and not peer_entity.gigagroup
        ):
            return True

    if ignore_gigagroups:
        if isinstance(peer_entity, telethon.types.Channel) and peer_entity.gigagroup:
            return True

    if member_ignore_threshold and member_ignore_threshold > 0:
        participants_count: Union[int, None] = None

        if isinstance(peer_entity, telethon.types.Channel):
            input_entity = await client.get_input_entity(peer_entity)
            input_channel = telethon.utils.get_input_channel(input_entity)
            request = telethon.tl.functions.channels.GetFullChannelRequest(
                channel=input_channel
            )
            channel_full_info = await client(request)
            full_chat: telethon.types.ChannelFull = channel_full_info.full_chat  # type: ignore
            participants_count = full_chat.participants_count
        elif isinstance(peer_entity, telethon.types.Chat):
            participants_count = peer_entity.participants_count

        if participants_count and participants_count >= member_ignore_threshold:
            return True

    return False


async def should_ignore_deleted_message(
    telegram_message: TelegramMessage,
    client: TelegramClient,
    ignore_channels: bool,
    ignore_groups: bool,
    ignore_megagroups: bool,
    ignore_gigagroups: bool,
    member_ignore_threshold: int,
    should_notify_outgoing_messages: bool,
) -> bool:
    """
    Determine if a deleted message notification should be ignored.

    This checks both the chat type filters and whether the message was outgoing
    (if should_notify_outgoing_messages is True).

    Args:
        telegram_message: The deleted message to check
        client: Telegram client for fetching peer entities
        ignore_channels: Whether to ignore channel messages
        ignore_groups: Whether to ignore regular group messages
        ignore_megagroups: Whether to ignore megagroup messages
        ignore_gigagroups: Whether to ignore gigagroup messages
        member_ignore_threshold: Minimum participant count to ignore
        should_notify_outgoing_messages: Whether to notify about outgoing messages

    Returns:
        True if the deleted message notification should be ignored, False otherwise
    """
    from packages.telegram_helpers import build_peer_entity

    chat_peer_entity: Union[
        telethon.types.User, telethon.types.Chat, telethon.types.Channel, None
    ] = await build_peer_entity(telegram_message.chat_peer, client)

    should_ignore_message_chat_result = await raw_should_ignore_message_chat(
        chat_peer_entity,
        client,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold,
    )

    if should_ignore_message_chat_result:
        return True

    if should_notify_outgoing_messages:
        from_peer_entity = await build_peer_entity(telegram_message.from_peer, client)
        my_user_peer_entity = await client.get_input_entity("me")
        if from_peer_entity == my_user_peer_entity:
            return True

    return False

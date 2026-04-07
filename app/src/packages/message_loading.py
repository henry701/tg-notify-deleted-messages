"""Message loading utilities for fetching messages from the database."""

import telethon
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import select
from telethon import TelegramClient

from packages.filtering import (
    raw_should_ignore_message_chat,
    should_ignore_deleted_message,
)
from packages.models.root.TelegramMessage import TelegramMessage
from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType


async def load_messages_from_db(
    ids: list[int],
    peer_entity: telethon.types.User
    | telethon.types.Chat
    | telethon.types.Channel
    | None,
    sqlalchemy_session: Session,
) -> tuple:
    """
    Load messages from the database matching the given IDs and optional peer entity.

    This function constructs a SQL query to find TelegramMessages with the specified IDs,
    optionally filtered by chat peer ID and peer type if a peer_entity is provided.

    Args:
        ids: List of message IDs to load
        peer_entity: Optional peer entity to filter by chat
        sqlalchemy_session: Database session for executing the query

    Returns:
        Tuple of (the_query, db_results, unloaded_ids) where:
        - the_query: The SQLAlchemy Select query object
        - db_results: List of TelegramMessage objects found in the database
        - unloaded_ids: List of IDs that were not found in the database
    """
    from sqlalchemy.sql.selectable import Select

    the_query: Select = select(TelegramMessage).where(TelegramMessage.id.in_(ids))
    peer_entity_id = peer_entity.id if peer_entity is not None else None
    if peer_entity_id is not None:
        the_query = the_query.where(
            TelegramMessage.chat_peer.has(TelegramPeer.peer_id == peer_entity_id)
        )
    chat_peer_type = PeerType.from_type(type(peer_entity))
    if chat_peer_type is not None:
        the_query = the_query.where(
            TelegramMessage.chat_peer.has(TelegramPeer.type == chat_peer_type)
        )
    db_results: list[TelegramMessage] = list(
        sqlalchemy_session.execute(the_query).scalars().all()
    )
    loaded_ids = [int(str(message.id)) for message in db_results]
    unloaded_ids = [msg_id for msg_id in ids if msg_id not in loaded_ids]
    return (the_query, db_results, unloaded_ids)


async def load_messages_by_parameters(
    ids: list[int],
    peer_entity: telethon.types.User
    | telethon.types.Chat
    | telethon.types.Channel
    | None,
    client: TelegramClient,
    sqlalchemy_session: Session,
    ignore_channels: bool,
    ignore_groups: bool,
    ignore_megagroups: bool,
    ignore_gigagroups: bool,
    member_ignore_threshold: int,
    should_load_outgoing_messages: bool,
):
    """
    Load messages from the database with filtering based on chat type.

    This function first checks if the peer entity should be ignored based on
    the filter configuration. If not ignored, it loads messages from the database
    and then filters the loaded messages based on deletion notification rules.

    Args:
        ids: List of message IDs to load
        peer_entity: Optional peer entity for filtering
        client: Telegram client for fetching additional info
        sqlalchemy_session: Database session for executing queries
        ignore_channels: Whether to ignore channel messages
        ignore_groups: Whether to ignore regular group messages
        ignore_megagroups: Whether to ignore megagroup messages
        ignore_gigagroups: Whether to ignore gigagroup messages
        member_ignore_threshold: Minimum participant count to ignore
        should_load_outgoing_messages: Whether to load outgoing messages

    Returns:
        Tuple of (filtered_results, the_query, unloaded_ids, filtered_away_ids) where:
        - filtered_results: Messages that passed all filters
        - the_query: The SQLAlchemy Select query object
        - unloaded_ids: IDs not found in the database
        - filtered_away_ids: IDs that were filtered out
    """

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
        member_ignore_threshold,
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
        db_results,
    )
    filtered_away_ids = [
        int(str(message.id))
        for message in db_results
        if message not in filtered_results
    ]

    return (filtered_results, the_query, unloaded_ids, filtered_away_ids)


async def filter_loaded_messages(
    ignore_channels: bool,
    ignore_groups: bool,
    ignore_megagroups: bool,
    ignore_gigagroups: bool,
    member_ignore_threshold: int,
    should_notify_outgoing_messages: bool,
    client: TelegramClient,
    db_results: list[TelegramMessage],
) -> list[TelegramMessage]:
    """
    Filter loaded messages based on deletion notification rules.

    This function filters out messages that should not trigger deletion notifications
    based on chat type filters and outgoing message settings.

    Args:
        ignore_channels: Whether to ignore channel messages
        ignore_groups: Whether to ignore regular group messages
        ignore_megagroups: Whether to ignore megagroup messages
        ignore_gigagroups: Whether to ignore gigagroup messages
        member_ignore_threshold: Minimum participant count to ignore
        should_notify_outgoing_messages: Whether to notify about outgoing messages
        client: Telegram client for fetching peer entities
        db_results: List of TelegramMessage objects to filter

    Returns:
        List of messages that should trigger deletion notifications
    """
    return [
        message
        for message in db_results
        if not await should_ignore_deleted_message(
            message,
            client,
            ignore_channels,
            ignore_groups,
            ignore_megagroups,
            ignore_gigagroups,
            member_ignore_threshold,
            should_notify_outgoing_messages,
        )
    ]

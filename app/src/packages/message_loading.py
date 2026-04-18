"""Message loading utilities for fetching messages from the database."""

import logging

import telethon
from sqlalchemy import func
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
from packages.runtime_diagnostics import format_process_runtime_snapshot

logger = logging.getLogger("tgdel-message-loading")


def describe_peer_entity(peer_entity) -> str:
    if peer_entity is None:
        return "peer=None"
    peer_type = type(peer_entity).__name__
    peer_id = getattr(peer_entity, "id", None)
    return f"peer_type={peer_type} peer_id={peer_id}"


def summarize_message_ids(ids: list[int], limit: int = 10) -> str:
    if len(ids) <= limit:
        return str(ids)
    return f"{ids[:limit]}...(+{len(ids) - limit} more)"


def apply_peer_filters_to_message_query(the_query, peer_entity):
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
    logger.debug(
        "Applied peer filters to message query: %s peer_type_filter=%s | %s",
        describe_peer_entity(peer_entity),
        chat_peer_type.name if chat_peer_type is not None else None,
        format_process_runtime_snapshot(),
    )
    return the_query


async def load_latest_messages_from_db(
    ids: list[int],
    peer_entity: telethon.types.User
    | telethon.types.Chat
    | telethon.types.Channel
    | None,
    sqlalchemy_session: Session,
) -> tuple:
    from sqlalchemy.sql.selectable import Select

    logger.debug(
        "Loading latest messages from DB for ids=%s count=%s %s | %s",
        summarize_message_ids(ids),
        len(ids),
        describe_peer_entity(peer_entity),
        format_process_runtime_snapshot(),
    )
    subq = (
        select(
            TelegramMessage.id,
            TelegramMessage.chat_peer_id,
            func.max(TelegramMessage.edit_date).label("max_edit_date"),
        )
        .where(TelegramMessage.id.in_(ids))
        .group_by(TelegramMessage.id, TelegramMessage.chat_peer_id)
        .subquery()
    )

    the_query: Select = select(TelegramMessage).join(
        subq,
        (TelegramMessage.id == subq.c.id)
        & (TelegramMessage.chat_peer_id == subq.c.chat_peer_id)
        & (TelegramMessage.edit_date == subq.c.max_edit_date),
    )
    the_query = apply_peer_filters_to_message_query(the_query, peer_entity)

    db_results: list[TelegramMessage] = list(
        sqlalchemy_session.execute(the_query).scalars().all()
    )
    loaded_ids = [int(str(message.id)) for message in db_results]
    unloaded_ids = [msg_id for msg_id in ids if msg_id not in loaded_ids]
    logger.debug(
        "Loaded latest messages from DB: loaded_count=%s unloaded_count=%s loaded_ids=%s unloaded_ids=%s %s | %s",
        len(db_results),
        len(unloaded_ids),
        summarize_message_ids(loaded_ids),
        summarize_message_ids(unloaded_ids),
        describe_peer_entity(peer_entity),
        format_process_runtime_snapshot(),
    )
    return (the_query, db_results, unloaded_ids)


async def load_messages_from_db(
    ids: list[int],
    peer_entity: telethon.types.User
    | telethon.types.Chat
    | telethon.types.Channel
    | None,
    sqlalchemy_session: Session,
) -> tuple:
    return await load_latest_messages_from_db(ids, peer_entity, sqlalchemy_session)


async def message_exists_in_db(
    message_id: int,
    peer_entity: telethon.types.User
    | telethon.types.Chat
    | telethon.types.Channel
    | None,
    sqlalchemy_session: Session,
) -> bool:
    logger.debug(
        "Checking whether message exists in DB for message_id=%s %s | %s",
        message_id,
        describe_peer_entity(peer_entity),
        format_process_runtime_snapshot(),
    )
    the_query = select(TelegramMessage.id).where(TelegramMessage.id == message_id).limit(1)
    the_query = apply_peer_filters_to_message_query(the_query, peer_entity)
    message_exists = sqlalchemy_session.execute(the_query).first() is not None
    logger.debug(
        "Finished message existence check for message_id=%s exists=%s %s | %s",
        message_id,
        message_exists,
        describe_peer_entity(peer_entity),
        format_process_runtime_snapshot(),
    )
    return message_exists


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
    logger.debug(
        "Loading messages by parameters for ids=%s count=%s %s ignore_channels=%s ignore_groups=%s ignore_megagroups=%s ignore_gigagroups=%s member_ignore_threshold=%s should_load_outgoing_messages=%s | %s",
        summarize_message_ids(ids),
        len(ids),
        describe_peer_entity(peer_entity),
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold,
        should_load_outgoing_messages,
        format_process_runtime_snapshot(),
    )
    if peer_entity and await raw_should_ignore_message_chat(
        peer_entity,
        client,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold,
    ):
        logger.debug(
            "Skipping DB message load because peer is filtered away: ids=%s %s | %s",
            summarize_message_ids(ids),
            describe_peer_entity(peer_entity),
            format_process_runtime_snapshot(),
        )
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
    logger.debug(
        "Completed load_messages_by_parameters: db_results=%s filtered_results=%s unloaded_ids=%s filtered_away_ids=%s %s | %s",
        len(db_results),
        len(filtered_results),
        summarize_message_ids(unloaded_ids),
        summarize_message_ids(filtered_away_ids),
        describe_peer_entity(peer_entity),
        format_process_runtime_snapshot(),
    )

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
    logger.debug(
        "Filtering loaded messages: candidate_count=%s should_notify_outgoing_messages=%s | %s",
        len(db_results),
        should_notify_outgoing_messages,
        format_process_runtime_snapshot(),
    )
    filtered_results = [
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
    logger.debug(
        "Finished filtering loaded messages: kept=%s filtered_away=%s | %s",
        len(filtered_results),
        len(db_results) - len(filtered_results),
        format_process_runtime_snapshot(),
    )
    return filtered_results

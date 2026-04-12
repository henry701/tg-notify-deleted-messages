import base64
import io
import json
import mimetypes
import os

from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import select
from telethon.client.telegramclient import TelegramClient
from telethon.events.messagedeleted import MessageDeleted
from telethon.tl import types as tl_types
from telethon.tl.types import (
    InputEncryptedChat,
    InputPeerChannel,
    InputPeerChat,
    InputPeerSelf,
    InputPeerUser,
    PeerChannel,
    PeerChat,
    PeerUser,
)

from packages.models.root.TelegramMessage import TelegramMessage
from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType


async def get_mention_text(entity):
    if not entity:
        mention_username = "Anonymous"
    elif getattr(entity, "title", None):
        mention_username = entity.title
    elif getattr(entity, "first_name", None) or getattr(entity, "last_name", None):
        mention_username = (
            getattr(entity, "first_name", "") + " "
            if getattr(entity, "first_name", "")
            else ""
        ) + (
            getattr(entity, "last_name", "") if getattr(entity, "last_name", "") else ""
        )
    elif getattr(entity, "username", None):
        mention_username = entity.username
    elif getattr(entity, "phone", None):
        mention_username = entity.phone
    else:
        mention_username = getattr(entity, "id", None)
        if not mention_username:
            mention_username = getattr(entity, "chat_id", None)
    if not mention_username:
        mention_username = "UNKNOWN. Type name: " + type(entity).__name__
    return mention_username


async def build_telegram_peer(
    peer: PeerUser | PeerChat | PeerChannel | None,
    client: TelegramClient,
    sqlalchemy_session_maker: sessionmaker,
) -> TelegramPeer | None:
    async def find_existing_peer(tele_peer, sqlalchemy_session):
        return sqlalchemy_session.execute(
            select(TelegramPeer)
            .where(TelegramPeer.peer_id == tele_peer.peer_id)
            .where(TelegramPeer.type == tele_peer.type)
        ).scalar()

    if peer is None:
        return None
    got_entity = await client.get_entity(peer)
    tele_peer = TelegramPeer(
        peer_id=await client.get_peer_id(peer=got_entity, add_mark=False),
        type=PeerType.from_type(type(got_entity), mandatory=True),
        access_hash=getattr(got_entity, "access_hash", None),
    )
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        existing_peer = await find_existing_peer(tele_peer, sqlalchemy_session)
    if existing_peer:
        return existing_peer
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        sqlalchemy_session.merge(tele_peer)
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        return await find_existing_peer(tele_peer, sqlalchemy_session)


def to_telethon_input_peer(
    telegram_peer: TelegramPeer,
) -> (
    InputPeerUser
    | InputPeerChannel
    | InputPeerChat
    | InputPeerSelf
    | InputEncryptedChat
    | None
):
    try:
        peer_type = PeerType(telegram_peer.type)
    except Exception:
        return None
    return peer_type.to_input_type(
        int(str(telegram_peer.peer_id)),
        int(str(telegram_peer.access_hash)) if telegram_peer.access_hash else None,
    )


async def refresh_client(client: TelegramClient):
    await client.get_dialogs()
    await client.get_me()
    await client.get_messages(limit=10)


async def build_peer_entity(peer: TelegramPeer, client: TelegramClient):
    if peer is None:
        return None
    input_peer = to_telethon_input_peer(peer)
    if input_peer is None:
        return None
    return await client.get_entity(input_peer)


async def get_message_user_and_chat_entities(
    client: TelegramClient,
    message: TelegramMessage,
    tried: bool = False,
):
    try:
        user = (
            await client.get_entity(to_telethon_input_peer(message.from_peer))
            if message.from_peer
            else None
        )
        chat = (
            await client.get_entity(to_telethon_input_peer(message.chat_peer))
            if message.chat_peer
            else None
        )
        return (user, chat)
    except ValueError:
        if tried:
            raise
        await refresh_client(client)
        return await get_message_user_and_chat_entities(
            client=client, message=message, tried=True
        )


def get_canonical_message_text(message) -> str:
    if message is None:
        return ""
    for attribute_name in ("raw_text", "message", "text"):
        value = getattr(message, attribute_name, None)
        if isinstance(value, str):
            return value
    return ""


def normalize_optional_string(value) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def get_message_media_metadata(message) -> tuple[str | None, str | None]:
    if message is None:
        return (None, None)
    message_file = getattr(message, "file", None)
    return (
        normalize_optional_string(getattr(message_file, "name", None)),
        normalize_optional_string(getattr(message_file, "mime_type", None)),
    )


def get_message_grouped_id(message) -> int | None:
    grouped_id = getattr(message, "grouped_id", None) if message is not None else None
    if grouped_id is None:
        return None
    try:
        return int(str(grouped_id))
    except (TypeError, ValueError):
        return None


def serialize_message_document_attributes(message) -> str | None:
    if message is None:
        return None
    document = getattr(message, "document", None)
    attributes = getattr(document, "attributes", None)
    if not attributes:
        return None

    serialized_attributes = []
    for attribute in attributes:
        if isinstance(attribute, tl_types.DocumentAttributeAudio):
            serialized_attributes.append(
                {
                    "type": "audio",
                    "duration": attribute.duration,
                    "voice": attribute.voice,
                    "title": attribute.title,
                    "performer": attribute.performer,
                    "waveform": (
                        base64.b64encode(attribute.waveform).decode("ascii")
                        if attribute.waveform is not None
                        else None
                    ),
                }
            )
        elif isinstance(attribute, tl_types.DocumentAttributeVideo):
            serialized_attributes.append(
                {
                    "type": "video",
                    "duration": attribute.duration,
                    "w": attribute.w,
                    "h": attribute.h,
                    "round_message": attribute.round_message,
                    "supports_streaming": attribute.supports_streaming,
                    "nosound": attribute.nosound,
                    "preload_prefix_size": attribute.preload_prefix_size,
                    "video_start_ts": attribute.video_start_ts,
                    "video_codec": attribute.video_codec,
                }
            )

    if not serialized_attributes:
        return None
    return json.dumps(serialized_attributes, separators=(",", ":"))


def deserialize_stored_document_attributes(
    message: TelegramMessage,
) -> list[tl_types.TypeDocumentAttribute] | None:
    deserialized_attributes: list[tl_types.TypeDocumentAttribute] = []
    resolved_file_name = resolve_stored_media_file_name(message)
    if resolved_file_name is not None:
        deserialized_attributes.append(
            tl_types.DocumentAttributeFilename(os.path.basename(resolved_file_name))
        )

    raw_serialized_attributes = normalize_optional_string(
        getattr(message, "media_document_attributes", None)
    )
    if raw_serialized_attributes is None:
        return deserialized_attributes or None

    try:
        loaded_attributes = json.loads(raw_serialized_attributes)
    except json.JSONDecodeError:
        return deserialized_attributes or None

    if not isinstance(loaded_attributes, list):
        return deserialized_attributes or None

    for raw_attribute in loaded_attributes:
        if not isinstance(raw_attribute, dict):
            continue
        attribute_type = raw_attribute.get("type")
        if attribute_type == "audio":
            waveform = raw_attribute.get("waveform")
            deserialized_attributes.append(
                tl_types.DocumentAttributeAudio(
                    duration=int(raw_attribute.get("duration") or 0),
                    voice=raw_attribute.get("voice"),
                    title=normalize_optional_string(raw_attribute.get("title")),
                    performer=normalize_optional_string(raw_attribute.get("performer")),
                    waveform=(
                        base64.b64decode(waveform)
                        if isinstance(waveform, str) and waveform
                        else None
                    ),
                )
            )
        elif attribute_type == "video":
            deserialized_attributes.append(
                tl_types.DocumentAttributeVideo(
                    duration=float(raw_attribute.get("duration") or 0),
                    w=int(raw_attribute.get("w") or 0),
                    h=int(raw_attribute.get("h") or 0),
                    round_message=raw_attribute.get("round_message"),
                    supports_streaming=raw_attribute.get("supports_streaming"),
                    nosound=raw_attribute.get("nosound"),
                    preload_prefix_size=raw_attribute.get("preload_prefix_size"),
                    video_start_ts=raw_attribute.get("video_start_ts"),
                    video_codec=normalize_optional_string(
                        raw_attribute.get("video_codec")
                    ),
                )
            )

    return deserialized_attributes or None


def resolve_stored_media_file_name(message: TelegramMessage) -> str | None:
    stored_file_name = normalize_optional_string(
        getattr(message, "media_file_name", None)
    )
    stored_mime_type = normalize_optional_string(
        getattr(message, "media_mime_type", None)
    )
    guessed_extension = (
        mimetypes.guess_extension(stored_mime_type, strict=False)
        if stored_mime_type is not None
        else None
    )

    if stored_file_name is not None:
        if guessed_extension and not os.path.splitext(stored_file_name)[1]:
            return stored_file_name + guessed_extension
        return stored_file_name
    if guessed_extension is not None:
        return f"attachment{guessed_extension}"
    return None


def build_stored_media_file(message: TelegramMessage) -> io.BytesIO | None:
    if getattr(message, "media", None) is None:
        return None
    media_stream = io.BytesIO(message.media)
    resolved_file_name = resolve_stored_media_file_name(message)
    if resolved_file_name is not None:
        media_stream.name = resolved_file_name
    media_stream.seek(0)
    return media_stream


async def send_stored_message_with_optional_media(
    sender_client: TelegramClient,
    entity,
    formatted_text: str,
    message: TelegramMessage,
):
    media_stream = build_stored_media_file(message)
    if media_stream is None:
        await sender_client.send_message(entity=entity, message=formatted_text)
        return

    send_file_kwargs = {
        "entity": entity,
        "file": media_stream,
        "caption": formatted_text,
    }
    stored_mime_type = normalize_optional_string(
        getattr(message, "media_mime_type", None)
    )
    if stored_mime_type is not None:
        send_file_kwargs["mime_type"] = stored_mime_type
    stored_attributes = deserialize_stored_document_attributes(message)
    if stored_attributes is not None:
        send_file_kwargs["attributes"] = stored_attributes
    await sender_client.send_file(**send_file_kwargs)


async def send_stored_messages_with_optional_media(
    sender_client: TelegramClient,
    entity,
    formatted_texts: list[str],
    messages: list[TelegramMessage],
):
    if not messages:
        return
    if len(messages) == 1:
        await send_stored_message_with_optional_media(
            sender_client=sender_client,
            entity=entity,
            formatted_text=formatted_texts[0],
            message=messages[0],
        )
        return

    first_grouped_id = getattr(messages[0], "grouped_id", None)
    media_streams = [build_stored_media_file(message) for message in messages]
    album_safe_mime_types = all(
        (normalize_optional_string(getattr(message, "media_mime_type", None)) is None)
        or normalize_optional_string(
            getattr(message, "media_mime_type", None)
        ).startswith(("image/", "video/"))
        for message in messages
    )
    can_send_as_album = (
        first_grouped_id is not None
        and all(
            getattr(message, "grouped_id", None) == first_grouped_id
            for message in messages
        )
        and all(media_stream is not None for media_stream in media_streams)
        and album_safe_mime_types
    )
    if not can_send_as_album:
        for message, formatted_text in zip(messages, formatted_texts):
            await send_stored_message_with_optional_media(
                sender_client=sender_client,
                entity=entity,
                formatted_text=formatted_text,
                message=message,
            )
        return

    await sender_client.send_file(
        entity=entity,
        file=media_streams,
        caption=formatted_texts,
    )


def build_chat_link(entity, message_id: int | None = None) -> str | None:
    if entity is None:
        return None
    peer_type = PeerType.from_type(type(entity))
    username = getattr(entity, "username", None)
    entity_id = getattr(entity, "id", None)
    is_channel_like = (
        peer_type == PeerType.CHANNEL
        or getattr(entity, "broadcast", None) is not None
        or getattr(entity, "megagroup", None) is not None
    )
    is_chat_like = (
        is_channel_like
        or peer_type == PeerType.CHAT
        or getattr(entity, "title", None) is not None
    )
    if username:
        if message_id is not None and is_chat_like:
            return f"tg://resolve?domain={username}&post={message_id}"
        return f"tg://resolve?domain={username}"
    if message_id is not None and is_channel_like and entity_id is not None:
        return f"tg://privatepost?channel={entity_id}&post={message_id}"
    phone = getattr(entity, "phone", None)
    if phone:
        return f"tg://resolve?phone={phone}"
    return None


def format_chat_reference(
    entity, fallback_name: str, message_id: int | None = None
) -> str:
    link = build_chat_link(entity, message_id=message_id)
    if link is None:
        return fallback_name
    return f"[{fallback_name}]({link})"


async def format_default_message_text(
    client: TelegramClient, message: TelegramMessage, tried: bool = False
):
    user, chat = await get_message_user_and_chat_entities(
        client=client, message=message, tried=tried
    )
    mention_username = await get_mention_text(user)
    mention_chatname = await get_mention_text(chat)
    chat_reference = format_chat_reference(
        chat,
        mention_chatname,
        message_id=(
            int(str(message.id)) if getattr(message, "id", None) is not None else None
        ),
    )
    text = "**Deleted message** from: [{username}](tg://user?id={userid}) on chat {chat_reference}\n".format(
        username=mention_username,
        userid=(str(user.id) if user else "0"),
        chat_reference=chat_reference,
    )
    if message.text:
        text += "**Message Text:** " + message.text
    return text


async def format_default_message_batch_texts(
    client: TelegramClient, messages: list[TelegramMessage]
) -> list[str]:
    if not messages:
        return []
    if len(messages) == 1:
        return [await format_default_message_text(client, messages[0])]

    user, chat = await get_message_user_and_chat_entities(
        client=client, message=messages[0]
    )
    mention_username = await get_mention_text(user)
    mention_chatname = await get_mention_text(chat)
    chat_reference = format_chat_reference(
        chat,
        mention_chatname,
        message_id=(
            int(str(messages[0].id))
            if getattr(messages[0], "id", None) is not None
            else None
        ),
    )
    texts = [
        "**Deleted album** ({count} items) from: [{username}](tg://user?id={userid}) on chat {chat_reference}\n".format(
            count=len(messages),
            username=mention_username,
            userid=(str(user.id) if user else "0"),
            chat_reference=chat_reference,
        )
    ]
    if messages[0].text:
        texts[0] += "**Message Text:** " + messages[0].text
    texts.extend(
        "**Message Text:** " + message.text if message.text else ""
        for message in messages[1:]
    )
    return texts


async def format_default_message_edit_text(
    client: TelegramClient, message: TelegramMessage, tried: bool = False
) -> str:
    user, chat = await get_message_user_and_chat_entities(
        client=client, message=message, tried=tried
    )
    mention_username = await get_mention_text(user)
    mention_chatname = await get_mention_text(chat)
    old_text = getattr(message, "edit_old_text", "") or ""
    new_text = message.text or ""
    chat_reference = format_chat_reference(
        chat,
        mention_chatname,
        message_id=(
            int(str(message.id)) if getattr(message, "id", None) is not None else None
        ),
    )
    return "**Edited message** from: [{username}](tg://user?id={userid}) on chat {chat_reference}\n**Old Text:** {old_text}\n**New Text:** {new_text}".format(
        username=mention_username,
        userid=(str(user.id) if user else "0"),
        chat_reference=chat_reference,
        old_text=old_text,
        new_text=new_text,
    )


async def format_default_unknown_message_text(
    client: TelegramClient,
    message_ids: list[int],
    event: MessageDeleted.Event,
    tried: bool = False,
) -> str:
    try:
        input_chat = await event.get_input_chat()
        chat = await client.get_entity(input_chat) if input_chat else None
    except ValueError:
        if tried:
            raise
        await refresh_client(client)
        return await format_default_unknown_message_text(
            client=client, message_ids=message_ids, event=event, tried=True
        )
    mention_chatname = await get_mention_text(chat)
    chat_reference = format_chat_reference(chat, mention_chatname)
    text = "**Unknown deleted messages** on chat {chat_reference}\n".format(
        chat_reference=chat_reference,
    )
    text += (
        "**Message IDs ("
        + str(len(message_ids))
        + " total):** "
        + ", ".join(str(x) for x in message_ids)
    )
    return text

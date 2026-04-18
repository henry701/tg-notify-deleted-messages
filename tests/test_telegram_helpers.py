import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType
from packages.telegram_helpers import (
    build_stored_media_file,
    build_chat_link,
    build_peer_entity,
    build_telegram_peer,
    deserialize_stored_document_attributes,
    format_default_message_edit_text,
    format_default_message_batch_texts,
    format_default_message_text,
    format_default_unknown_message_text,
    get_canonical_message_text,
    get_message_grouped_id,
    get_message_media_metadata,
    get_mention_text,
    refresh_client,
    resolve_stored_media_file_name,
    send_stored_messages_with_optional_media,
    send_stored_message_with_optional_media,
    should_persist_message_media,
    serialize_message_document_attributes,
    to_telethon_input_peer,
)
from telethon.tl.types import (
    DocumentAttributeAudio,
    DocumentAttributeVideo,
    InputPeerChannel,
    InputPeerChat,
    InputPeerSelf,
    InputPeerUser,
    MessageMediaWebPage,
)


class GetMentionTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_title_when_entity_has_title(self):
        entity = MagicMock()
        entity.title = "My Channel"
        result = await get_mention_text(entity)
        self.assertEqual(result, "My Channel")

    async def test_returns_first_and_last_name(self):
        entity = MagicMock()
        entity.first_name = "John"
        entity.last_name = "Doe"
        entity.title = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "John Doe")

    async def test_returns_first_name_only(self):
        entity = MagicMock()
        entity.first_name = "John"
        entity.last_name = ""
        entity.title = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "John ")

    async def test_returns_last_name_only(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = "Doe"
        entity.title = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "Doe")

    async def test_returns_username_when_no_name(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = "johndoe"
        result = await get_mention_text(entity)
        self.assertEqual(result, "johndoe")

    async def test_returns_phone_when_no_name_or_username(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = "123456789"
        result = await get_mention_text(entity)
        self.assertEqual(result, "123456789")

    async def test_returns_id_when_no_name_username_or_phone(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = None
        entity.id = 42
        result = await get_mention_text(entity)
        self.assertEqual(result, 42)

    async def test_returns_chat_id_when_no_other_identifiers(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = None
        entity.id = None
        entity.chat_id = 99
        result = await get_mention_text(entity)
        self.assertEqual(result, 99)

    async def test_returns_anonymous_for_none_entity(self):
        result = await get_mention_text(None)
        self.assertEqual(result, "Anonymous")

    async def test_returns_type_name_when_no_identifiable_info(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = None
        entity.id = None
        entity.chat_id = None
        result = await get_mention_text(entity)
        self.assertIn("UNKNOWN", result)


class GetCanonicalMessageTextTests(unittest.TestCase):
    def test_prefers_raw_text_over_formatted_text(self):
        message = MagicMock()
        message.raw_text = "plain text"
        message.message = "plain text"
        message.text = "**plain text**"

        result = get_canonical_message_text(message)

        self.assertEqual(result, "plain text")

    def test_returns_empty_string_when_no_text_is_available(self):
        message = MagicMock()
        message.raw_text = None
        message.message = None
        message.text = None

        result = get_canonical_message_text(message)

        self.assertEqual(result, "")


class GetMessageMediaMetadataTests(unittest.TestCase):
    def test_extracts_filename_and_mime_type_from_message_file(self):
        message = MagicMock()
        message.file = MagicMock()
        message.file.name = "report.pdf"
        message.file.mime_type = "application/pdf"

        result = get_message_media_metadata(message)

        self.assertEqual(result, ("report.pdf", "application/pdf"))

    def test_ignores_non_string_metadata_values(self):
        message = MagicMock()
        message.file = MagicMock()
        message.file.name = MagicMock()
        message.file.mime_type = MagicMock()

        result = get_message_media_metadata(message)

        self.assertEqual(result, (None, None))

    def test_ignores_webpage_media_metadata(self):
        message = MagicMock()
        message.media = MessageMediaWebPage(webpage=MagicMock())
        message.file = MagicMock()
        message.file.name = "preview.mp4"
        message.file.mime_type = "video/mp4"

        result = get_message_media_metadata(message)

        self.assertEqual(result, (None, None))


class GetMessageGroupedIdTests(unittest.TestCase):
    def test_extracts_integer_grouped_id(self):
        message = MagicMock()
        message.grouped_id = 123456789

        self.assertEqual(get_message_grouped_id(message), 123456789)

    def test_returns_none_for_invalid_grouped_id(self):
        message = MagicMock()
        message.grouped_id = MagicMock()

        self.assertIsNone(get_message_grouped_id(message))


class SerializeMessageDocumentAttributesTests(unittest.TestCase):
    def test_serializes_audio_and_video_attributes(self):
        message = MagicMock()
        message.document = MagicMock()
        message.document.attributes = [
            DocumentAttributeAudio(
                duration=12,
                voice=True,
                title="Voice title",
                performer="Performer",
                waveform=b"\x00\x01",
            ),
            DocumentAttributeVideo(
                duration=5,
                w=640,
                h=360,
                round_message=False,
                supports_streaming=True,
            ),
        ]

        serialized = serialize_message_document_attributes(message)
        restored_message = MagicMock()
        restored_message.media_file_name = "voice.ogg"
        restored_message.media_mime_type = "audio/ogg"
        restored_message.media_document_attributes = serialized

        restored_attributes = deserialize_stored_document_attributes(restored_message)

        assert restored_attributes is not None
        audio_attribute = next(
            attr
            for attr in restored_attributes
            if isinstance(attr, DocumentAttributeAudio)
        )
        video_attribute = next(
            attr
            for attr in restored_attributes
            if isinstance(attr, DocumentAttributeVideo)
        )
        self.assertTrue(audio_attribute.voice)
        self.assertEqual(audio_attribute.duration, 12)
        self.assertEqual(audio_attribute.title, "Voice title")
        self.assertEqual(audio_attribute.performer, "Performer")
        self.assertEqual(audio_attribute.waveform, b"\x00\x01")
        self.assertEqual(video_attribute.duration, 5)
        self.assertEqual(video_attribute.w, 640)
        self.assertEqual(video_attribute.h, 360)
        self.assertTrue(video_attribute.supports_streaming)

    def test_ignores_webpage_media(self):
        message = MagicMock()
        message.media = MessageMediaWebPage(webpage=MagicMock())
        message.document = MagicMock()
        message.document.attributes = [
            DocumentAttributeVideo(
                duration=5,
                w=640,
                h=360,
                round_message=False,
                supports_streaming=True,
            )
        ]

        serialized = serialize_message_document_attributes(message)

        self.assertIsNone(serialized)


class ShouldPersistMessageMediaTests(unittest.TestCase):
    def test_returns_false_for_webpage_media(self):
        message = MagicMock()
        message.media = MessageMediaWebPage(webpage=MagicMock())

        self.assertFalse(should_persist_message_media(message))

    def test_returns_true_for_regular_media(self):
        message = MagicMock()
        message.media = MagicMock()

        self.assertTrue(should_persist_message_media(message))


class ResolveStoredMediaFileNameTests(unittest.TestCase):
    def test_prefers_stored_file_name_when_present(self):
        message = MagicMock()
        message.media_file_name = "invoice.pdf"
        message.media_mime_type = "application/pdf"

        result = resolve_stored_media_file_name(message)

        self.assertEqual(result, "invoice.pdf")

    def test_synthesizes_extension_from_mime_type_when_missing(self):
        message = MagicMock()
        message.media_file_name = None
        message.media_mime_type = "image/jpeg"

        result = resolve_stored_media_file_name(message)

        self.assertEqual(result, "attachment.jpg")

    def test_appends_extension_when_name_has_none(self):
        message = MagicMock()
        message.media_file_name = "attachment"
        message.media_mime_type = "text/plain"

        result = resolve_stored_media_file_name(message)

        self.assertEqual(result, "attachment.txt")


class BuildStoredMediaFileTests(unittest.TestCase):
    def test_builds_named_bytes_io_for_stored_media(self):
        message = MagicMock()
        message.media = b"binary-data"
        message.media_file_name = "photo.jpg"
        message.media_mime_type = "image/jpeg"

        media_file = build_stored_media_file(message)

        self.assertIsNotNone(media_file)
        assert media_file is not None
        self.assertEqual(media_file.name, "photo.jpg")
        self.assertEqual(media_file.read(), b"binary-data")

    def test_returns_none_when_message_has_no_media(self):
        message = MagicMock()
        message.media = None

        self.assertIsNone(build_stored_media_file(message))


class SendStoredMessageWithOptionalMediaTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_send_message_when_no_media_is_present(self):
        sender_client = AsyncMock()
        message = MagicMock()
        message.media = None

        await send_stored_message_with_optional_media(
            sender_client,
            "me",
            "formatted text",
            message,
        )

        sender_client.send_message.assert_awaited_once_with(
            entity="me",
            message="formatted text",
        )
        sender_client.send_file.assert_not_called()

    async def test_uses_send_file_with_named_stream_and_mime_type(self):
        sender_client = AsyncMock()
        message = MagicMock()
        message.media = b"binary-data"
        message.media_file_name = "document.pdf"
        message.media_mime_type = "application/pdf"

        await send_stored_message_with_optional_media(
            sender_client,
            "me",
            "formatted text",
            message,
        )

        sender_client.send_file.assert_awaited_once()
        send_kwargs = sender_client.send_file.await_args.kwargs
        self.assertEqual(send_kwargs["entity"], "me")
        self.assertEqual(send_kwargs["caption"], "formatted text")
        self.assertEqual(send_kwargs["mime_type"], "application/pdf")
        self.assertEqual(send_kwargs["file"].name, "document.pdf")
        self.assertEqual(send_kwargs["file"].read(), b"binary-data")
        self.assertEqual(len(send_kwargs["attributes"]), 1)
        sender_client.send_message.assert_not_called()

    async def test_uses_stored_document_attributes_for_audio(self):
        sender_client = AsyncMock()
        message = MagicMock()
        message.media = b"audio-data"
        message.media_file_name = "voice.ogg"
        message.media_mime_type = "audio/ogg"
        message.media_document_attributes = (
            '[{"type":"audio","duration":7,"voice":true,"title":"Voice",'
            '"performer":"Bot","waveform":"AAE="}]'
        )

        await send_stored_message_with_optional_media(
            sender_client,
            "me",
            "formatted text",
            message,
        )

        send_kwargs = sender_client.send_file.await_args.kwargs
        self.assertEqual(send_kwargs["mime_type"], "audio/ogg")
        audio_attribute = next(
            attr
            for attr in send_kwargs["attributes"]
            if isinstance(attr, DocumentAttributeAudio)
        )
        self.assertTrue(audio_attribute.voice)
        self.assertEqual(audio_attribute.duration, 7)
        self.assertEqual(audio_attribute.title, "Voice")
        self.assertEqual(audio_attribute.performer, "Bot")
        self.assertEqual(audio_attribute.waveform, b"\x00\x01")


class SendStoredMessagesWithOptionalMediaTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_grouped_messages_as_album(self):
        sender_client = AsyncMock()
        first_message = MagicMock()
        first_message.grouped_id = 555
        first_message.media = b"first"
        first_message.media_file_name = "first.jpg"
        first_message.media_mime_type = "image/jpeg"
        first_message.media_document_attributes = None

        second_message = MagicMock()
        second_message.grouped_id = 555
        second_message.media = b"second"
        second_message.media_file_name = "second.jpg"
        second_message.media_mime_type = "image/jpeg"
        second_message.media_document_attributes = None

        await send_stored_messages_with_optional_media(
            sender_client=sender_client,
            entity="me",
            formatted_texts=["first caption", "second caption"],
            messages=[first_message, second_message],
        )

        sender_client.send_file.assert_awaited_once()
        send_kwargs = sender_client.send_file.await_args.kwargs
        self.assertEqual(send_kwargs["caption"], ["first caption", "second caption"])
        self.assertEqual(len(send_kwargs["file"]), 2)
        self.assertEqual(send_kwargs["file"][0].name, "first.jpg")
        self.assertEqual(send_kwargs["file"][1].name, "second.jpg")

    async def test_falls_back_to_individual_sends_when_album_is_not_replayable(self):
        sender_client = AsyncMock()
        first_message = MagicMock()
        first_message.grouped_id = 555
        first_message.media = b"first"
        first_message.media_file_name = "first.jpg"
        first_message.media_mime_type = "image/jpeg"
        first_message.media_document_attributes = None

        second_message = MagicMock()
        second_message.grouped_id = 555
        second_message.media = None
        second_message.media_file_name = None
        second_message.media_mime_type = None
        second_message.media_document_attributes = None

        await send_stored_messages_with_optional_media(
            sender_client=sender_client,
            entity="me",
            formatted_texts=["first caption", "second caption"],
            messages=[first_message, second_message],
        )

        self.assertEqual(sender_client.send_file.await_count, 1)
        sender_client.send_message.assert_awaited_once_with(
            entity="me",
            message="second caption",
        )


class BuildChatLinkTests(unittest.TestCase):
    def test_builds_private_post_link_for_private_channels(self):
        entity = MagicMock()
        entity.username = None
        entity.id = 200
        entity.phone = None
        entity.broadcast = None
        entity.megagroup = True
        entity.title = "Private Channel"

        result = build_chat_link(entity, message_id=10)

        self.assertEqual(result, "tg://privatepost?channel=200&post=10")

    def test_builds_domain_link_without_post_for_direct_message_users(self):
        entity = MagicMock()
        entity.username = "deletedmessagesbot"
        entity.id = 300
        entity.phone = None
        entity.broadcast = None
        entity.megagroup = None
        entity.title = None

        result = build_chat_link(entity, message_id=15)

        self.assertEqual(result, "tg://resolve?domain=deletedmessagesbot")


class ToTelethonInputPeerTests(unittest.TestCase):
    def test_user_type_with_access_hash_returns_input_peer_user(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=200,
            type=PeerType.USER,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerUser)
        self.assertEqual(result.user_id, 100)
        self.assertEqual(result.access_hash, 200)

    def test_user_type_without_access_hash_returns_input_peer_self(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=None,
            type=PeerType.USER,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerSelf)

    def test_channel_type_returns_input_peer_channel(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=200,
            type=PeerType.CHANNEL,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerChannel)
        self.assertEqual(result.channel_id, 100)
        self.assertEqual(result.access_hash, 200)

    def test_chat_type_returns_input_peer_chat(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=None,
            type=PeerType.CHAT,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerChat)
        self.assertEqual(result.chat_id, 100)

    def test_encrypted_chat_type_returns_input_encrypted_chat(self):
        from telethon.tl.types import InputEncryptedChat

        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=200,
            type=PeerType.ENCRYPTED_CHAT,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputEncryptedChat)
        self.assertEqual(result.chat_id, 100)
        self.assertEqual(result.access_hash, 200)

    def test_encrypted_chat_type_without_access_hash_returns_input_encrypted_chat(self):
        from telethon.tl.types import InputEncryptedChat

        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=None,
            type=PeerType.ENCRYPTED_CHAT,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputEncryptedChat)


class BuildPeerEntityTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_none_for_none_peer(self):
        client = AsyncMock()
        result = await build_peer_entity(None, client)
        self.assertIsNone(result)

    async def test_returns_none_for_peer_with_none_input_type(self):
        client = AsyncMock()
        # Create a TelegramPeer with an unknown type value that won't map to an InputPeer
        peer = MagicMock(spec=TelegramPeer)
        peer.id = 1
        peer.peer_id = 100
        peer.access_hash = None
        peer.type = 99  # Unknown type that won't map to any InputPeer
        result = await build_peer_entity(peer, client)
        self.assertIsNone(result)

    async def test_returns_entity_for_valid_peer(self):
        client = AsyncMock()
        mock_entity = MagicMock()
        client.get_entity.return_value = mock_entity

        peer = MagicMock(spec=TelegramPeer)
        peer.id = 1
        peer.peer_id = 100
        peer.access_hash = 200
        peer.type = PeerType.USER

        result = await build_peer_entity(peer, client)
        self.assertIs(result, mock_entity)
        client.get_entity.assert_called_once()


class RefreshClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_calls_expected_client_methods(self):
        client = AsyncMock()
        await refresh_client(client)
        client.get_dialogs.assert_called_once()
        client.get_me.assert_called_once()
        client.get_messages.assert_called_once_with(limit=10)


class BuildTelegramPeerTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_none_for_none_peer(self):
        client = AsyncMock()
        session_maker = MagicMock()
        result = await build_telegram_peer(None, client, session_maker)
        self.assertIsNone(result)


class GetMentionTextEdgeCaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_username_when_entity_has_username(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = "johndoe"
        entity.phone = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "johndoe")

    async def test_returns_phone_when_only_phone(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = "+1234567890"
        entity.id = None
        entity.chat_id = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "+1234567890")

    async def test_returns_first_name_with_trailing_space(self):
        entity = MagicMock()
        entity.first_name = "Alice"
        entity.last_name = ""
        entity.title = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "Alice ")


class FormatDefaultMessageTextRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_retries_on_first_valueerror_then_succeeds(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()

        user_entity = MagicMock()
        user_entity.id = 100
        user_entity.first_name = "John"
        user_entity.last_name = None
        user_entity.title = None
        user_entity.username = None
        user_entity.phone = None
        user_entity.chat_id = None

        chat_entity = MagicMock()
        chat_entity.id = 200
        chat_entity.title = "Retry Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None

        call_count = 0

        async def get_entity_side_effect(entity):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Entity not found")
            if call_count == 2:
                return user_entity
            return chat_entity

        client.get_entity = get_entity_side_effect

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text="Hello",
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            with patch(
                "packages.telegram_helpers.refresh_client", new_callable=AsyncMock
            ):
                result = await format_default_message_text(client, message)

        self.assertIn("John", result)
        self.assertIn("Retry Chat", result)
        self.assertIn("Hello", result)


class FormatDefaultMessageTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_formats_message_with_user_and_chat(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        user_entity = MagicMock()
        user_entity.id = 100
        user_entity.first_name = "John"
        user_entity.last_name = "Doe"
        user_entity.title = None
        user_entity.username = None
        user_entity.phone = None
        user_entity.chat_id = None

        chat_entity = MagicMock()
        chat_entity.id = 200
        chat_entity.title = "Test Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None
        chat_entity.megagroup = True

        client.get_entity.side_effect = [user_entity, chat_entity]

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text="Hello",
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            result = await format_default_message_text(client, message)

        self.assertIn("John Doe", result)
        self.assertIn("Test Chat", result)
        self.assertIn("Hello", result)
        self.assertIn("tg://privatepost?channel=200&post=1", result)

    async def test_formats_message_with_no_text(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        user_entity = MagicMock()
        user_entity.id = 100
        user_entity.first_name = "John"
        user_entity.title = None
        user_entity.last_name = ""
        user_entity.username = None
        user_entity.phone = None
        user_entity.chat_id = None

        chat_entity = MagicMock()
        chat_entity.id = 200
        chat_entity.title = "Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None
        chat_entity.megagroup = False

        client.get_entity.side_effect = [user_entity, chat_entity]

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text=None,
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            result = await format_default_message_text(client, message)

        self.assertIn("Deleted message", result)
        self.assertNotIn("**Message Text:**", result)

    async def test_formats_album_batch_with_single_header(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        user_entity = MagicMock()
        user_entity.id = 100
        user_entity.first_name = "John"
        user_entity.last_name = "Doe"
        user_entity.title = None
        user_entity.username = None
        user_entity.phone = None
        user_entity.chat_id = None

        chat_entity = MagicMock()
        chat_entity.id = 200
        chat_entity.title = "Album Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None
        chat_entity.megagroup = True

        client.get_entity.side_effect = [user_entity, chat_entity]

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        messages = [
            TelegramMessage(
                id=1,
                from_peer=from_peer,
                chat_peer=chat_peer,
                text="first",
                media=b"a",
                timestamp=None,
            ),
            TelegramMessage(
                id=2,
                from_peer=from_peer,
                chat_peer=chat_peer,
                text="second",
                media=b"b",
                timestamp=None,
            ),
        ]

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            result = await format_default_message_batch_texts(client, messages)

        self.assertEqual(len(result), 2)
        self.assertIn("Deleted album", result[0])
        self.assertIn("first", result[0])
        self.assertEqual(result[1], "**Message Text:** second")
        self.assertNotIn("tg://chat?id=", result)

    async def test_raises_on_second_valueerror(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        client.get_entity = AsyncMock(side_effect=ValueError("Still not found"))

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text="test",
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            with patch(
                "packages.telegram_helpers.refresh_client", new_callable=AsyncMock
            ):
                with self.assertRaises(ValueError):
                    await format_default_message_text(client, message, tried=True)


class FormatDefaultMessageEditTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_formats_edited_message_with_user_and_chat(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        user_entity = MagicMock()
        user_entity.id = 100
        user_entity.first_name = "John"
        user_entity.last_name = "Doe"
        user_entity.title = None
        user_entity.username = None
        user_entity.phone = None
        user_entity.chat_id = None

        chat_entity = MagicMock()
        chat_entity.id = 200
        chat_entity.title = "Edited Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None
        chat_entity.megagroup = True

        client.get_entity.side_effect = [user_entity, chat_entity]

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text="updated text",
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            message.edit_old_text = "previous text"
            result = await format_default_message_edit_text(client, message)

        self.assertIn("Edited message", result)
        self.assertIn("John Doe", result)
        self.assertIn("Edited Chat", result)
        self.assertIn("previous text", result)
        self.assertIn("updated text", result)
        self.assertIn("tg://privatepost?channel=200&post=1", result)


class FormatDefaultUnknownMessageTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_formats_unknown_deleted_messages(self):
        client = AsyncMock()
        chat_entity = MagicMock()
        chat_entity.id = 300
        chat_entity.title = "Unknown Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None
        client.get_entity.return_value = chat_entity

        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=MagicMock())

        result = await format_default_unknown_message_text(
            client, [10, 20, 30], event_mock
        )

        self.assertIn("Unknown deleted messages", result)
        self.assertIn("Unknown Chat", result)
        self.assertIn("3 total", result)
        self.assertIn("10", result)
        self.assertIn("20", result)
        self.assertIn("30", result)

    async def test_handles_none_chat(self):
        client = AsyncMock()
        client.get_entity.return_value = None

        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=None)

        result = await format_default_unknown_message_text(client, [5], event_mock)

        self.assertIn("Anonymous", result)
        self.assertIn("1 total", result)

    async def test_retries_on_valueerror_then_succeeds(self):
        client = AsyncMock()
        chat_entity = MagicMock()
        chat_entity.id = 300
        chat_entity.title = "Retry Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None

        mock_input = MagicMock()
        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=mock_input)

        call_count = 0

        async def get_entity_side_effect(entity):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Entity not found")
            return chat_entity

        client.get_entity = get_entity_side_effect

        with patch("packages.telegram_helpers.refresh_client", new_callable=AsyncMock):
            result = await format_default_unknown_message_text(
                client, [10, 20], event_mock
            )

        self.assertIn("Retry Chat", result)
        self.assertIn("2 total", result)

    async def test_raises_on_second_valueerror(self):
        client = AsyncMock()
        mock_input = MagicMock()
        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=mock_input)

        client.get_entity = AsyncMock(side_effect=ValueError("Still not found"))

        with patch("packages.telegram_helpers.refresh_client", new_callable=AsyncMock):
            with self.assertRaises(ValueError):
                await format_default_unknown_message_text(
                    client, [10], event_mock, tried=True
                )


class BuildTelegramPeerExistingTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_existing_peer_from_db(self):
        from telethon.tl.types import User

        client = AsyncMock()
        existing_peer = MagicMock(spec=TelegramPeer)
        existing_peer.peer_id = 100
        existing_peer.type = PeerType.USER

        session_mock = MagicMock()
        session_mock.execute.return_value.scalar.return_value = existing_peer

        session_maker = MagicMock()
        session_maker.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker.begin.return_value.__exit__ = MagicMock(return_value=False)

        mock_entity = User(id=100)
        mock_entity.access_hash = 123
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.get_peer_id = AsyncMock(return_value=100)

        peer_input = MagicMock()
        peer_input.peer_id = 100
        peer_input.type = PeerType.USER

        result = await build_telegram_peer(peer_input, client, session_maker)

        self.assertIs(result, existing_peer)

    async def test_creates_and_returns_new_peer(self):
        from telethon.tl.types import Channel, ChatPhotoEmpty

        client = AsyncMock()
        new_peer = MagicMock(spec=TelegramPeer)
        new_peer.peer_id = 200
        new_peer.type = PeerType.CHANNEL

        call_count = 0

        def scalar_side_effect():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None
            return new_peer

        session_mock = MagicMock()
        session_mock.execute.return_value.scalar.side_effect = scalar_side_effect

        session_maker = MagicMock()
        session_maker.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker.begin.return_value.__exit__ = MagicMock(return_value=False)

        mock_entity = Channel(id=200, title="Test", photo=ChatPhotoEmpty(), date=None)
        mock_entity.access_hash = 12345
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.get_peer_id = AsyncMock(return_value=200)

        peer_input = MagicMock()
        peer_input.peer_id = 200
        peer_input.type = PeerType.CHANNEL

        result = await build_telegram_peer(peer_input, client, session_maker)

        self.assertIs(result, new_peer)
        self.assertEqual(session_mock.execute.call_count, 2)
        session_mock.merge.assert_called_once()


if __name__ == "__main__":
    unittest.main()

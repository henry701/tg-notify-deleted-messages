import unittest

from telethon.tl.types import (
    EncryptedChat,
    InputEncryptedChat,
    InputPeerChannel,
    InputPeerChat,
    InputPeerSelf,
    InputPeerUser,
    PeerChannel,
    PeerChat,
    PeerUser,
)

from packages.models.support.PeerType import PeerType


class PeerTypeTests(unittest.TestCase):
    def test_from_type_maps_peer_types(self) -> None:
        self.assertEqual(PeerType.from_type(PeerUser), PeerType.USER)
        self.assertEqual(PeerType.from_type(PeerChannel), PeerType.CHANNEL)
        self.assertEqual(PeerType.from_type(PeerChat), PeerType.CHAT)

    def test_from_type_raises_when_mandatory_and_unsupported(self) -> None:
        with self.assertRaises(ValueError):
            PeerType.from_type(str, mandatory=True)

    def test_to_input_type_returns_input_peer_user(self) -> None:
        input_peer = PeerType.USER.to_input_type(10, 20)
        self.assertIsInstance(input_peer, InputPeerUser)
        self.assertEqual(input_peer.user_id, 10)
        self.assertEqual(input_peer.access_hash, 20)

    def test_to_input_type_returns_input_peer_self_without_access_hash(self) -> None:
        input_peer = PeerType.USER.to_input_type(10, None)
        self.assertIsInstance(input_peer, InputPeerSelf)

    def test_to_input_type_returns_input_peer_channel(self) -> None:
        input_peer = PeerType.CHANNEL.to_input_type(10, 20)
        self.assertIsInstance(input_peer, InputPeerChannel)
        self.assertEqual(input_peer.channel_id, 10)
        self.assertEqual(input_peer.access_hash, 20)

    def test_to_input_type_returns_input_peer_chat(self) -> None:
        input_peer = PeerType.CHAT.to_input_type(10, None)
        self.assertIsInstance(input_peer, InputPeerChat)
        self.assertEqual(input_peer.chat_id, 10)

    def test_from_type_maps_encrypted_chat(self) -> None:
        self.assertEqual(PeerType.from_type(EncryptedChat), PeerType.ENCRYPTED_CHAT)

    def test_to_input_type_returns_input_encrypted_chat(self) -> None:
        input_peer = PeerType.ENCRYPTED_CHAT.to_input_type(10, 20)
        self.assertIsInstance(input_peer, InputEncryptedChat)
        self.assertEqual(input_peer.chat_id, 10)
        self.assertEqual(input_peer.access_hash, 20)

    def test_to_input_type_encrypted_chat_without_access_hash(self) -> None:
        input_peer = PeerType.ENCRYPTED_CHAT.to_input_type(10, None)
        self.assertIsInstance(input_peer, InputEncryptedChat)
        self.assertEqual(input_peer.chat_id, 10)

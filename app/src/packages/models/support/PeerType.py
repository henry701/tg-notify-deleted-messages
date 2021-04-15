from enum import IntEnum
from typing import Type, Union

from telethon.tl.types import Channel, ChannelFull, Chat, ChatFull, EncryptedChat, InputChannel, InputEncryptedChat, InputPeerChannel, InputPeerChat, InputPeerSelf, InputPeerUser, InputUser, PeerChannel, PeerChat, PeerUser, User, UserFull

class PeerType(IntEnum):

    USER = 1
    CHANNEL = 2
    CHAT = 3
    ENCRYPTED_CHAT = 4

    @staticmethod
    def from_type(_type : Type, mandatory = False):
        if issubclass(_type, (PeerUser, User, UserFull, InputUser, InputPeerUser, InputPeerSelf)):
            return PeerType.USER
        if issubclass(_type, (PeerChannel, Channel, ChannelFull, InputChannel, InputPeerChannel)):
            return PeerType.CHANNEL
        if issubclass(_type, (PeerChat, Chat, ChatFull, InputPeerChat)):
            return PeerType.CHAT
        if issubclass(_type, (EncryptedChat, InputEncryptedChat)):
            return PeerType.ENCRYPTED_CHAT
        if mandatory:
            raise ValueError(f"Unable to get PeerType for type: {_type}")
        return None

    def to_input_type(self, id : int, hash : Union[int, None], mandatory = False) -> Union[InputPeerUser, InputPeerChannel, InputPeerChat]:
        if self == PeerType.USER:
            return InputPeerUser(id, hash)
        if self == PeerType.CHANNEL:
            return InputPeerChannel(id, hash)
        if self == PeerType.CHAT:
            return InputPeerChat(id)
        if self == PeerType.ENCRYPTED_CHAT:
            return InputPeerChat(id, hash)
        if mandatory:
            raise ValueError(f"Unable to get InputPeer from PeerType: {self}")
        return None

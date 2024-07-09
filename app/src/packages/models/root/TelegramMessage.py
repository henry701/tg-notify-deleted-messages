# -*- coding: utf-8 -*-

from sqlalchemy import Column, BigInteger, UnicodeText, LargeBinary, TIMESTAMP, Boolean
from sqlalchemy.sql.schema import ForeignKey

from packages.models.root.TelegramPeer import TelegramPeer

from .. import Base, encrypt_type_searchable, encrypt_type_safer

from sqlalchemy.orm import relationship

class TelegramMessage(Base):
    __tablename__ = 'telegram_messages'
    id = Column(encrypt_type_searchable(BigInteger()), nullable=False, primary_key=True, autoincrement=False)
    chat_peer_id = Column(BigInteger, ForeignKey(TelegramPeer.id), nullable=False, primary_key=True, index = True)
    chat_peer = relationship(TelegramPeer, lazy=False, cascade="all", foreign_keys=[chat_peer_id])
    from_peer_id = Column(BigInteger, ForeignKey(TelegramPeer.id), index = True)
    from_peer = relationship(TelegramPeer, lazy=False, cascade="all", foreign_keys=[from_peer_id])
    text = Column(encrypt_type_safer(UnicodeText()))
    media = Column(encrypt_type_safer(LargeBinary()))
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False, index = True)
    deleted = Column(Boolean(), nullable=False, default=False, index = True)

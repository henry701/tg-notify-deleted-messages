# -*- coding: utf-8 -*-

from sqlalchemy import Column, Integer, BigInteger
from sqlalchemy.sql.schema import UniqueConstraint

from .. import Base, encrypt_type_searchable

class TelegramPeer(Base):
    __tablename__ = 'telegram_peers'
    id = Column(BigInteger(), nullable=False, primary_key=True, autoincrement=True)
    peer_id = Column(encrypt_type_searchable(BigInteger()), nullable=False)
    access_hash = Column(encrypt_type_searchable(BigInteger()))
    # TODO: https://stackoverflow.com/questions/33612625/how-to-model-enums-backed-by-integers-with-sqlachemy
    type = Column(Integer(), nullable=False)
    __table_args__ = (
        UniqueConstraint(peer_id, type),
        {},
    )

# -*- coding: utf-8 -*-

from datetime import timezone
from sqlalchemy import Column, Integer, String, BLOB, TIMESTAMP, Boolean
from sqlalchemy.sql.schema import UniqueConstraint

from .. import Base, encrypt_type_searchable, encrypt_type_safer

class TelegramPeer(Base):
    __tablename__ = 'telegram_peers'
    id = Column(encrypt_type_searchable(Integer()), nullable=False, primary_key=True, autoincrement=True)
    peer_id = Column(encrypt_type_searchable(Integer()), nullable=False)
    access_hash = Column(encrypt_type_searchable(Integer()))
    # TODO: https://stackoverflow.com/questions/33612625/how-to-model-enums-backed-by-integers-with-sqlachemy
    type = Column(Integer(), nullable=False)
    __table_args__ = (
        UniqueConstraint(peer_id, type),
        {},
    )

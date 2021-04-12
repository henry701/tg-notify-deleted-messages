# -*- coding: utf-8 -*-

from datetime import timezone
from sqlalchemy import Column, Integer, String, BLOB, TIMESTAMP, Boolean

from . import Base, encrypt_type_searchable, encrypt_type_safer

class TelegramMessage(Base):
    __tablename__ = 'telegram_messages'
    id = Column(encrypt_type_searchable(Integer()), nullable=False, primary_key=True)
    peer_id = Column(encrypt_type_searchable(Integer()), nullable=False, primary_key=True)
    from_id = Column(encrypt_type_searchable(Integer()))
    text = Column(encrypt_type_safer(String(4096)))
    media = Column(encrypt_type_safer(BLOB()))
    timestamp = Column(encrypt_type_searchable(TIMESTAMP(timezone=timezone.utc)), nullable=False)
    deleted = Column(encrypt_type_searchable(Boolean()), nullable=False, default=False)

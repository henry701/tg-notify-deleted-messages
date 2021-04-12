from sqlalchemy import Column, Integer, String, BLOB, TIMESTAMP, Boolean

from . import Base, encrypt_type

class TelegramMessage(Base):
    __tablename__ = 'telegram_messages'
    id = Column(Integer(), nullable=False, primary_key=True)
    peer_id = Column(Integer(), nullable=False, primary_key=True)
    from_id = Column(Integer())
    text = Column(encrypt_type(String(4096)))
    media = Column(encrypt_type(BLOB))
    timestamp = Column(TIMESTAMP, nullable=False)
    deleted = Column(Boolean, nullable=False, default=False)

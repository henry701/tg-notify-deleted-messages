from sqlalchemy import Column, Integer, String, BLOB, TIMESTAMP, Boolean
from . import Base

class TelegramMessage(Base):
    __tablename__ = 'telegram_messages'
    id = Column(Integer(), nullable=False, primary_key=True)
    peer_id = Column(Integer(), nullable=False, primary_key=True)
    from_id = Column(Integer())
    text = Column(String(4096))
    media = Column(BLOB)
    timestamp = Column(TIMESTAMP, nullable=False)
    deleted = Column(Boolean, nullable=False, default=False)

from sqlalchemy import Column, Integer, String, BLOB, TIMESTAMP
from . import Base

class TelegramMessage(Base):
    __tablename__ = 'telegram_messages'
    id = Column(Integer(), unique=True, nullable=False, primary_key=True)
    from_id = Column(Integer())
    text = Column(String(4096))
    media = Column(BLOB)
    timestamp = Column(TIMESTAMP, nullable=False)

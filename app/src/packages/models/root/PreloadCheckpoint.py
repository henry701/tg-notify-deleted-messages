from packages.models.root.TelegramPeer import TelegramPeer
from sqlalchemy import TIMESTAMP, BigInteger, Column
from sqlalchemy.orm import relationship
from sqlalchemy.sql.schema import ForeignKey

from .. import Base, encrypt_type_searchable


class PreloadCheckpoint(Base):
    __tablename__ = "preload_checkpoints"

    chat_peer_id = Column(
        BigInteger,
        ForeignKey(TelegramPeer.id),
        nullable=False,
        primary_key=True,
        index=True,
    )
    chat_peer = relationship(
        TelegramPeer, lazy=False, cascade="all", foreign_keys=[chat_peer_id]
    )

    preloaded_through_message_id = Column(
        encrypt_type_searchable(BigInteger()),
        nullable=True,
    )
    preloaded_through_timestamp = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        index=True,
    )
    updated_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        index=True,
    )

from datetime import datetime, timezone

from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import delete, select

from packages.models.root.PreloadCheckpoint import PreloadCheckpoint
from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType


def get_preload_checkpoint(
    chat_peer_id: int, sqlalchemy_session_maker: sessionmaker
) -> PreloadCheckpoint | None:
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        return sqlalchemy_session.execute(
            select(PreloadCheckpoint).where(
                PreloadCheckpoint.chat_peer_id == chat_peer_id
            )
        ).scalar_one_or_none()


def upsert_preload_checkpoint(
    chat_peer_id: int,
    preloaded_through_timestamp: datetime,
    sqlalchemy_session_maker: sessionmaker,
    preloaded_through_message_id: int | None = None,
) -> PreloadCheckpoint:
    checkpoint = PreloadCheckpoint(
        chat_peer_id=chat_peer_id,
        preloaded_through_message_id=preloaded_through_message_id,
        preloaded_through_timestamp=preloaded_through_timestamp,
        updated_at=datetime.now(tz=timezone.utc),
    )
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        sqlalchemy_session.merge(checkpoint)
    loaded_checkpoint = get_preload_checkpoint(chat_peer_id, sqlalchemy_session_maker)
    if loaded_checkpoint is None:
        raise RuntimeError(
            f"Failed to upsert preload checkpoint for chat_peer_id={chat_peer_id}"
        )
    return loaded_checkpoint


def clear_preload_checkpoint(
    chat_peer_id: int, sqlalchemy_session_maker: sessionmaker
) -> int:
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        result = sqlalchemy_session.execute(
            delete(PreloadCheckpoint).where(
                PreloadCheckpoint.chat_peer_id == chat_peer_id
            )
        )
    return int(result.rowcount or 0)


def clear_all_preload_checkpoints(sqlalchemy_session_maker: sessionmaker) -> int:
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        result = sqlalchemy_session.execute(delete(PreloadCheckpoint))
    return int(result.rowcount or 0)


def list_preload_checkpoints(
    sqlalchemy_session_maker: sessionmaker,
) -> list[PreloadCheckpoint]:
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        return list(
            sqlalchemy_session.execute(
                select(PreloadCheckpoint).order_by(
                    PreloadCheckpoint.updated_at.desc(),
                    PreloadCheckpoint.chat_peer_id.asc(),
                )
            )
            .scalars()
            .all()
        )


def find_chat_peer_id_for_checkpoint_query(
    sqlalchemy_session_maker: sessionmaker,
    chat_peer_id: int | None = None,
    peer_id: int | None = None,
    peer_type: PeerType | None = None,
) -> int | None:
    if chat_peer_id is not None:
        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            peer = sqlalchemy_session.execute(
                select(TelegramPeer).where(TelegramPeer.id == int(chat_peer_id))
            ).scalar_one_or_none()
        if peer is None:
            return None
        return int(peer.id)
    if peer_id is None or peer_type is None:
        return None
    with sqlalchemy_session_maker.begin() as sqlalchemy_session:
        peer = sqlalchemy_session.execute(
            select(TelegramPeer)
            .where(TelegramPeer.peer_id == peer_id)
            .where(TelegramPeer.type == int(peer_type))
        ).scalar_one_or_none()
    if peer is None:
        return None
    return int(peer.id)

import enum
from sqlalchemy import String, Boolean, Text, Integer, BigInteger, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class Visibility(str, enum.Enum):
    PUBLIC = "public"
    UNLISTED = "unlisted"
    PRIVATE = "private"


class Image(TimestampMixin, Base):
    __tablename__ = "images"

    short_code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    visibility: Mapped[Visibility] = mapped_column(
        Enum(Visibility), default=Visibility.PUBLIC, nullable=False
    )
    nsfw: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    views: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    owner = relationship("User", back_populates="images", lazy="selectin")
    comments = relationship(
        "Comment", back_populates="image", lazy="selectin", cascade="all, delete-orphan"
    )
    votes = relationship(
        "Vote", back_populates="image", lazy="selectin", cascade="all, delete-orphan"
    )
    album_entries = relationship(
        "AlbumImage", back_populates="image", lazy="selectin", cascade="all, delete-orphan"
    )

    @property
    def vote_score(self) -> int:
        return sum(v.value for v in self.votes) if self.votes else 0

    @property
    def extension(self) -> str:
        parts = self.original_name.rsplit(".", 1)
        return parts[-1].lower() if len(parts) > 1 else ""

    def __str__(self) -> str:
        owner_name = self.owner.username if self.owner else "anonymous"
        return (
            f"Image(code={self.short_code}, name={self.original_name}, "
            f"size={self.size_bytes}, owner={owner_name}, views={self.views})"
        )

    def __repr__(self) -> str:
        return self.__str__()

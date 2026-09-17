from sqlalchemy import String, Text, Integer, ForeignKey, Enum, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin
from app.models.image import Visibility


class Album(TimestampMixin, Base):
    __tablename__ = "albums"

    short_code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    visibility: Mapped[Visibility] = mapped_column(
        Enum(Visibility), default=Visibility.PUBLIC, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    owner = relationship("User", back_populates="albums", lazy="selectin")
    entries = relationship(
        "AlbumImage",
        back_populates="album",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="AlbumImage.position",
    )

    @property
    def images(self):
        return [entry.image for entry in self.entries if entry.image]

    @property
    def cover(self):
        return self.images[0] if self.images else None

    @property
    def image_count(self) -> int:
        return len(self.entries)

    def __str__(self) -> str:
        return (
            f"Album(code={self.short_code}, title={self.title}, "
            f"images={self.image_count}, owner={self.owner.username if self.owner else 'unknown'})"
        )

    def __repr__(self) -> str:
        return self.__str__()


class AlbumImage(Base):
    __tablename__ = "album_images"
    __table_args__ = (
        UniqueConstraint("album_id", "image_id", name="uq_album_image"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    album_id: Mapped[int] = mapped_column(
        ForeignKey("albums.id", ondelete="CASCADE"), nullable=False
    )
    image_id: Mapped[int] = mapped_column(
        ForeignKey("images.id", ondelete="CASCADE"), nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    album = relationship("Album", back_populates="entries")
    image = relationship("Image", back_populates="album_entries")

    def __str__(self) -> str:
        return f"AlbumImage(album={self.album_id}, image={self.image_id}, pos={self.position})"

    def __repr__(self) -> str:
        return self.__str__()

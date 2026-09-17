from sqlalchemy import String, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class User(TimestampMixin, Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)

    images = relationship("Image", back_populates="owner", lazy="selectin")
    albums = relationship("Album", back_populates="owner", lazy="selectin")
    comments = relationship("Comment", back_populates="author", lazy="selectin")
    votes = relationship("Vote", back_populates="user", lazy="selectin")

    def __str__(self) -> str:
        return f"User(id={self.id}, email={self.email}, admin={self.is_admin})".format(self=self)

    def __repr__(self) -> str:
        return self.__str__()

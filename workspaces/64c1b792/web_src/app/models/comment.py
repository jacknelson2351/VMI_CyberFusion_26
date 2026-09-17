from sqlalchemy import Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class Comment(TimestampMixin, Base):
    __tablename__ = "comments"

    body: Mapped[str] = mapped_column(Text, nullable=False)
    image_id: Mapped[int] = mapped_column(
        ForeignKey("images.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    image = relationship("Image", back_populates="comments")
    author = relationship("User", back_populates="comments", lazy="selectin")

    def __str__(self) -> str:
        author_name = self.author.username if self.author else "unknown"
        preview = self.body[:16] + "..." if len(self.body) > 16 else self.body
        return f"Comment(id={self.id}, author={author_name}, body={preview})".format(
            self=self,
            author_name=author_name,
            preview=preview,
        )

    def __repr__(self) -> str:
        return self.__str__()

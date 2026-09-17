from sqlalchemy import Integer, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class Vote(TimestampMixin, Base):
    __tablename__ = "votes"
    __table_args__ = (
        UniqueConstraint("image_id", "user_id", name="uq_vote_per_user"),
    )

    value: Mapped[int] = mapped_column(Integer, nullable=False)  # +1 or -1
    image_id: Mapped[int] = mapped_column(
        ForeignKey("images.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    image = relationship("Image", back_populates="votes")
    user = relationship("User", back_populates="votes", lazy="selectin")

    @property
    def is_upvote(self) -> bool:
        return self.value > 0

    def __str__(self) -> str:
        direction = "up" if self.is_upvote else "down"
        user_name = self.user.username if self.user else "unknown"
        return f"Vote(id={self.id}, {direction}, user={user_name}, image={self.image_id})"

    def __repr__(self) -> str:
        return self.__str__()

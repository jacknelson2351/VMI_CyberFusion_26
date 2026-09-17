from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ImageUpload(BaseModel):
    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    visibility: str = Field(default="public", pattern=r"^(public|unlisted|private)$")
    nsfw: bool = False


class ImageResponse(BaseModel):
    id: int
    short_code: str
    original_name: str
    content_type: str
    size_bytes: int
    width: Optional[int] = None
    height: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    visibility: str
    nsfw: bool
    views: int
    vote_score: int = 0
    comment_count: int = 0
    owner_name: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ImageLinks(BaseModel):
    page: str
    direct: str
    thumbnail: str
    markdown: str
    html: str
    bbcode: str

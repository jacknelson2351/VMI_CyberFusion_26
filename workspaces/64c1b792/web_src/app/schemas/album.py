from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class AlbumCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    visibility: str = Field(default="public", pattern=r"^(public|unlisted|private)$")


class AlbumResponse(BaseModel):
    id: int
    short_code: str
    title: str
    description: Optional[str] = None
    visibility: str
    image_count: int = 0
    owner_name: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

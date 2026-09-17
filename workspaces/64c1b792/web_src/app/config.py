import os
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://pixelvault:changeme@localhost:5432/pixelvault"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "changeme")
    STORAGE_PATH: str = "/data/uploads"
    MAX_UPLOAD_MB: int = 20
    ALLOWED_EXTENSIONS: str = "png,jpg,jpeg,gif,webp,tiff"
    SITE_NAME: str = "PixelVault"
    SITE_URL: str = os.environ.get("SITE_URL", "http://localhost:8000")
    THUMB_SIZES: str = "150,320,640"
    LOG_LEVEL: str = "info"
    TOKEN_EXPIRE_HOURS: int = 72
    RATE_LIMIT_PER_MINUTE: int = 60

    @property
    def allowed_extensions_list(self) -> List[str]:
        return [e.strip().lower() for e in self.ALLOWED_EXTENSIONS.split(",")]

    @property
    def thumb_sizes_list(self) -> List[int]:
        return [int(s.strip()) for s in self.THUMB_SIZES.split(",")]

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_MB * 1024 * 1024

    class Config:
        env_file = ".env"
        case_sensitive = True

    def __str__(self) -> str:
        return (
            f"Settings(site={self.SITE_NAME}, url={self.SITE_URL}, "
            f"max_upload={self.MAX_UPLOAD_MB}MB, extensions={self.ALLOWED_EXTENSIONS})"
        ).format(self=self)

    def __repr__(self) -> str:
        return self.__str__()


settings = Settings()

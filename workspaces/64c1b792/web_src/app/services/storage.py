import os
import aiofiles
from datetime import datetime, timezone
from pathlib import Path
from app.config import settings


def _date_subdir() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y/%m/%d")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


async def save_file(filename: str, data: bytes) -> str:
    subdir = _date_subdir()
    dir_path = Path(settings.STORAGE_PATH) / "originals" / subdir
    _ensure_dir(dir_path)
    file_path = dir_path / filename
    async with aiofiles.open(file_path, "wb") as f:
        await f.write(data)
    return str(file_path)


async def save_thumbnail(filename: str, data: bytes, size: int) -> str:
    subdir = _date_subdir()
    dir_path = Path(settings.STORAGE_PATH) / "thumbs" / str(size) / subdir
    _ensure_dir(dir_path)
    file_path = dir_path / filename
    async with aiofiles.open(file_path, "wb") as f:
        await f.write(data)
    return str(file_path)


def get_file_path(filename: str, created_at: datetime) -> Path:
    subdir = created_at.strftime("%Y/%m/%d")
    return Path(settings.STORAGE_PATH) / "originals" / subdir / filename


def get_thumb_path(filename: str, created_at: datetime, size: int) -> Path:
    subdir = created_at.strftime("%Y/%m/%d")
    thumb_name = f"{Path(filename).stem}.webp"
    return Path(settings.STORAGE_PATH) / "thumbs" / str(size) / subdir / thumb_name


async def delete_file(filename: str, created_at: datetime) -> None:
    file_path = get_file_path(filename, created_at)
    if file_path.exists():
        os.remove(file_path)
    for size in settings.thumb_sizes_list:
        thumb_path = get_thumb_path(filename, created_at, size)
        if thumb_path.exists():
            os.remove(thumb_path)

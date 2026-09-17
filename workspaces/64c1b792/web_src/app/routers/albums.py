from fastapi import APIRouter, Depends, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from app.dependencies import get_db, get_current_user, require_auth
from app.models.user import User
from app.models.image import Image, Visibility
from app.models.album import Album, AlbumImage
from app.services import shortcode
from app.config import settings

router = APIRouter(tags=["albums"])


@router.get("/album/new", response_class=HTMLResponse)
async def new_album_page(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Image).where(Image.user_id == user.id).order_by(Image.created_at.desc())
    )
    user_images = result.scalars().all()
    return request.app.state.templates.TemplateResponse(
        "album/new.html",
        {"request": request, "settings": settings, "user": user, "images": user_images},
    )


@router.post("/album")
async def create_album(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    visibility: str = Form("public"),
    image_ids: list[int] = Form(default=[]),
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    vis = Visibility(visibility) if visibility in [v.value for v in Visibility] else Visibility.PUBLIC
    code = shortcode.generate()

    album = Album(
        short_code=code,
        title=title,
        description=description,
        visibility=vis,
        user_id=user.id,
    )
    db.add(album)
    await db.flush()

    for pos, img_id in enumerate(image_ids):
        result = await db.execute(select(Image).where(Image.id == img_id, Image.user_id == user.id))
        img = result.scalar_one_or_none()
        if img:
            entry = AlbumImage(album_id=album.id, image_id=img.id, position=pos)
            db.add(entry)

    return RedirectResponse(f"/album/{code}", status_code=status.HTTP_302_FOUND)


@router.get("/album/{code}", response_class=HTMLResponse)
async def view_album(
    code: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    result = await db.execute(select(Album).where(Album.short_code == code))
    album = result.scalar_one_or_none()

    if not album:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Album not found")

    if album.visibility == Visibility.PRIVATE:
        if not user or (user.id != album.user_id and not user.is_admin):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Album not found")

    return request.app.state.templates.TemplateResponse(
        "album/view.html",
        {"request": request, "settings": settings, "user": user, "album": album},
    )


@router.post("/album/{code}/add")
async def add_to_album(
    code: str,
    image_id: int = Form(...),
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Album).where(Album.short_code == code, Album.user_id == user.id))
    album = result.scalar_one_or_none()
    if not album:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Album not found")

    result = await db.execute(select(Image).where(Image.id == image_id, Image.user_id == user.id))
    image = result.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

    max_pos = max((e.position for e in album.entries), default=-1) + 1
    entry = AlbumImage(album_id=album.id, image_id=image.id, position=max_pos)
    db.add(entry)

    return RedirectResponse(f"/album/{code}", status_code=status.HTTP_302_FOUND)

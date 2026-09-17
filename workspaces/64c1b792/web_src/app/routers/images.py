from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.image import Image, Visibility
from app.services.storage import get_file_path, get_thumb_path
from app.config import settings

router = APIRouter(tags=["images"])


@router.get("/i/{code}", response_class=HTMLResponse)
async def view_image(
    code: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    result = await db.execute(select(Image).where(Image.short_code == code))
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

    if image.visibility == Visibility.PRIVATE:
        if not user or (user.id != image.user_id and not user.is_admin):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

    image.views += 1
    await db.flush()

    user_vote = None
    if user and image.votes:
        for v in image.votes:
            if v.user_id == user.id:
                user_vote = v.value
                break

    return request.app.state.templates.TemplateResponse(
        "image.html",
        {
            "request": request,
            "settings": settings,
            "user": user,
            "image": image,
            "user_vote": user_vote,
        },
    )


@router.get("/raw/{code}")
async def raw_image(
    code: str,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    result = await db.execute(select(Image).where(Image.short_code == code))
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

    if image.visibility == Visibility.PRIVATE:
        if not user or (user.id != image.user_id and not user.is_admin):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

    path = get_file_path(image.filename, image.created_at)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    return FileResponse(
        path=str(path),
        media_type=image.content_type,
        filename=image.original_name,
    )


@router.get("/thumb/{code}/{size}")
async def thumbnail(
    code: str,
    size: int,
    db: AsyncSession = Depends(get_db),
):
    if size not in settings.thumb_sizes_list:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid thumbnail size")

    result = await db.execute(select(Image).where(Image.short_code == code))
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

    if image.visibility == Visibility.PRIVATE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

    path = get_thumb_path(image.filename, image.created_at, size)
    if not path.exists():
        full_path = get_file_path(image.filename, image.created_at)
        if full_path.exists():
            return FileResponse(path=str(full_path), media_type=image.content_type)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Thumbnail not found")

    return FileResponse(path=str(path), media_type="image/webp")

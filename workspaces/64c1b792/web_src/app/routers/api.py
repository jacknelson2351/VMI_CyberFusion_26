import logging
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from app.dependencies import get_db, get_current_user, require_auth
from app.models.user import User
from app.models.image import Image, Visibility
from app.models.comment import Comment
from app.models.vote import Vote
from app.schemas.image import ImageResponse, ImageLinks
from app.schemas.comment import CommentCreate, CommentResponse
from app.services import shortcode, storage, processing
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["api"])


@router.post("/upload", response_model=list[ImageResponse])
async def api_upload(
    files: list[UploadFile] = File(...),
    title: Optional[str] = Form(None),
    visibility: str = Form("public"),
    nsfw: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    results = []
    for file in files:
        data = await file.read()
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail=f"{file.filename}: too large")

        mime = processing.validate_file_type(data, file.filename)
        if not mime:
            raise HTTPException(status_code=415, detail=f"{file.filename}: unsupported type")

        if not processing.is_valid_image(data):
            raise HTTPException(status_code=400, detail=f"{file.filename}: not a valid image")

        width, height = processing.get_dimensions(data, mime)
        code = shortcode.generate()
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else "bin"
        stored_name = f"{code}.{ext}"

        await storage.save_file(stored_name, data)
        for size in settings.thumb_sizes_list:
            thumb_data = processing.generate_thumbnail(data, mime, size)
            if thumb_data:
                await storage.save_thumbnail(stored_name, thumb_data, size)

        vis = Visibility(visibility) if visibility in [v.value for v in Visibility] else Visibility.PUBLIC
        image = Image(
            short_code=code,
            filename=stored_name,
            original_name=file.filename,
            content_type=mime,
            size_bytes=len(data),
            width=width,
            height=height,
            title=title,
            visibility=vis,
            nsfw=nsfw,
            user_id=user.id if user else None,
        )
        db.add(image)
        await db.flush()
        results.append(ImageResponse(
            id=image.id,
            short_code=image.short_code,
            original_name=image.original_name,
            content_type=image.content_type,
            size_bytes=image.size_bytes,
            width=image.width,
            height=image.height,
            title=image.title,
            description=image.description,
            visibility=image.visibility.value,
            nsfw=image.nsfw,
            views=image.views,
            vote_score=0,
            comment_count=0,
            owner_name=user.username if user else None,
            created_at=image.created_at,
        ))
    return results


@router.get("/images/{code}")
async def api_get_image(
    code: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Image).where(Image.short_code == code))
    image = result.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Not found")

    base = settings.SITE_URL.rstrip("/")
    return {
        "image": ImageResponse(
            id=image.id,
            short_code=image.short_code,
            original_name=image.original_name,
            content_type=image.content_type,
            size_bytes=image.size_bytes,
            width=image.width,
            height=image.height,
            title=image.title,
            description=image.description,
            visibility=image.visibility.value,
            nsfw=image.nsfw,
            views=image.views,
            vote_score=image.vote_score,
            comment_count=len(image.comments) if image.comments else 0,
            owner_name=image.owner.username if image.owner else None,
            created_at=image.created_at,
        ).model_dump(),
        "links": ImageLinks(
            page=f"{base}/i/{image.short_code}",
            direct=f"{base}/raw/{image.short_code}",
            thumbnail=f"{base}/thumb/{image.short_code}/{settings.thumb_sizes_list[0]}",
            markdown=f"![{image.original_name}]({base}/raw/{image.short_code})",
            html=f'<img src="{base}/raw/{image.short_code}" alt="{image.original_name}">',
            bbcode=f"[img]{base}/raw/{image.short_code}[/img]",
        ).model_dump(),
    }


@router.post("/images/{code}/vote")
async def api_vote(
    code: str,
    value: int = Form(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    if value not in (1, -1):
        raise HTTPException(status_code=400, detail="Vote must be 1 or -1")

    result = await db.execute(select(Image).where(Image.short_code == code))
    image = result.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Not found")

    existing = await db.execute(
        select(Vote).where(Vote.image_id == image.id, Vote.user_id == user.id)
    )
    vote = existing.scalar_one_or_none()

    if vote:
        if vote.value == value:
            await db.delete(vote)
            return {"status": "removed", "score": image.vote_score - value}
        else:
            vote.value = value
    else:
        vote = Vote(image_id=image.id, user_id=user.id, value=value)
        logger.info("New vote: %s", vote)
        db.add(vote)

    await db.flush()
    await db.refresh(image)
    return {"status": "voted", "value": value, "score": image.vote_score}


@router.post("/images/{code}/comment", response_model=CommentResponse)
async def api_comment(
    code: str,
    body: str = Form(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    if not body or len(body) > 2000:
        raise HTTPException(status_code=400, detail="Comment must be 1-2000 characters")

    result = await db.execute(select(Image).where(Image.short_code == code))
    image = result.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Not found")

    comment = Comment(body=body, image_id=image.id, user_id=user.id)
    db.add(comment)
    await db.flush()
    logger.info("New comment: %s", comment)
    await db.refresh(comment)

    return CommentResponse(
        id=comment.id,
        body=comment.body,
        author_name=user.username,
        created_at=comment.created_at,
    )


@router.delete("/images/{code}")
async def api_delete(
    code: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    result = await db.execute(select(Image).where(Image.short_code == code))
    image = result.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Not found")
    if image.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")

    logger.info("Deleting: %s", image)
    await storage.delete_file(image.filename, image.created_at)
    await db.delete(image)
    return {"status": "deleted"}


@router.get("/health")
async def health():
    return {"status": "ok"}

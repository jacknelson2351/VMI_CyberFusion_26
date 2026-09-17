import logging
from fastapi import APIRouter, Depends, Request, UploadFile, File, Form, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional, List
from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.image import Image, Visibility
from app.services import shortcode, storage, processing
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["upload"])


@router.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    result = await db.execute(
        select(Image)
        .where(Image.visibility == Visibility.PUBLIC)
        .order_by(desc(Image.created_at))
        .limit(12)
    )
    recent = result.scalars().all()
    return request.app.state.templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "settings": settings,
            "user": user,
            "recent_images": recent,
        },
    )


@router.post("/upload", response_class=HTMLResponse)
async def upload_images(
    request: Request,
    files: List[UploadFile] = File(...),
    title: Optional[str] = Form(None),
    visibility: str = Form("public"),
    nsfw: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    if not files or (len(files) == 1 and files[0].filename == ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No files provided")

    uploaded = []
    errors = []

    for file in files:
        data = await file.read()

        if len(data) > settings.max_upload_bytes:
            errors.append(f"{file.filename}: exceeds {settings.MAX_UPLOAD_MB}MB limit")
            continue

        mime = processing.validate_file_type(data, file.filename)
        if not mime:
            errors.append(f"{file.filename}: unsupported file type")
            continue

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
        logger.info("Uploaded: %s", image)
        uploaded.append(image)

    return request.app.state.templates.TemplateResponse(
        "uploaded.html",
        {
            "request": request,
            "settings": settings,
            "user": user,
            "images": uploaded,
            "errors": errors,
        },
    )

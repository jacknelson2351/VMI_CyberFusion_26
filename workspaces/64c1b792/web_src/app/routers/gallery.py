from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.image import Image, Visibility
from app.models.vote import Vote
from app.config import settings

router = APIRouter(tags=["gallery"])

PAGE_SIZE = 24


@router.get("/gallery", response_class=HTMLResponse)
async def gallery(
    request: Request,
    sort: str = Query("newest", pattern=r"^(newest|top|trending)$"),
    page: int = Query(1, ge=1),
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    query = select(Image).where(
        Image.visibility == Visibility.PUBLIC,
    )

    if sort == "newest":
        query = query.order_by(desc(Image.created_at))
    elif sort == "top":
        vote_score = (
            select(func.coalesce(func.sum(Vote.value), 0))
            .where(Vote.image_id == Image.id)
            .correlate(Image)
            .scalar_subquery()
        )
        query = query.order_by(desc(vote_score))
    elif sort == "trending":
        vote_score = (
            select(func.coalesce(func.sum(Vote.value), 0))
            .where(Vote.image_id == Image.id)
            .correlate(Image)
            .scalar_subquery()
        )
        query = query.order_by(desc(Image.views + vote_score * 10))

    offset = (page - 1) * PAGE_SIZE
    query = query.offset(offset).limit(PAGE_SIZE + 1)

    result = await db.execute(query)
    images = list(result.scalars().all())

    has_next = len(images) > PAGE_SIZE
    if has_next:
        images = images[:PAGE_SIZE]

    return request.app.state.templates.TemplateResponse(
        "gallery.html",
        {
            "request": request,
            "settings": settings,
            "user": user,
            "images": images,
            "sort": sort,
            "page": page,
            "has_next": has_next,
        },
    )

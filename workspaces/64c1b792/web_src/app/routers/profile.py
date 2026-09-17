from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.image import Image, Visibility
from app.config import settings

router = APIRouter(tags=["profile"])


@router.get("/u/{username}", response_class=HTMLResponse)
async def user_profile(
    username: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    result = await db.execute(select(User).where(User.username == username))
    profile_user = result.scalar_one_or_none()

    if not profile_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    is_own_profile = user and user.id == profile_user.id

    img_query = select(Image).where(Image.user_id == profile_user.id)
    if not is_own_profile:
        img_query = img_query.where(Image.visibility == Visibility.PUBLIC)
    img_query = img_query.order_by(Image.created_at.desc())

    result = await db.execute(img_query)
    images = result.scalars().all()

    count_result = await db.execute(
        select(func.count()).select_from(Image).where(Image.user_id == profile_user.id)
    )
    total_images = count_result.scalar()

    return request.app.state.templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "settings": settings,
            "user": user,
            "profile_user": profile_user,
            "images": images,
            "total_images": total_images,
            "is_own_profile": is_own_profile,
        },
    )

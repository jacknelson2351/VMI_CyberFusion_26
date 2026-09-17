import logging
from fastapi import APIRouter, Depends, Request, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import ValidationError
from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin
from app.services.auth import hash_password, verify_password, create_token, set_auth_cookie, clear_auth_cookie
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user: User | None = Depends(get_current_user)):
    if user:
        return RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    return request.app.state.templates.TemplateResponse(
        "auth/login.html",
        {"request": request, "settings": settings, "user": None},
    )


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    try:
        UserLogin(username=username, password=password)
    except ValidationError:
        return request.app.state.templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "settings": settings, "user": None, "error": "Invalid username or password format"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.password_hash):
        return request.app.state.templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "settings": settings, "user": None, "error": "Invalid credentials"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    logger.info("User logged in: %s", user)
    token = create_token(user.id, user.username)
    response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    set_auth_cookie(response, token)
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, user: User | None = Depends(get_current_user)):
    if user:
        return RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    return request.app.state.templates.TemplateResponse(
        "auth/register.html",
        {"request": request, "settings": settings, "user": None},
    )


@router.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    try:
        user_in = UserCreate(username=username, email=email, password=password)
    except ValidationError as e:
        errors = [err["msg"] for err in e.errors()]
        return request.app.state.templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "settings": settings, "user": None, "error": "; ".join(errors)},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    existing = await db.execute(
        select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    )
    if existing.scalar_one_or_none():
        return request.app.state.templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "settings": settings, "user": None, "error": "Username or email already taken"},
            status_code=status.HTTP_409_CONFLICT,
        )

    user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=hash_password(user_in.password),
    )
    db.add(user)
    await db.flush()

    token = create_token(user.id, user.username)
    response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    set_auth_cookie(response, token)
    return response


@router.post("/logout")
async def logout():
    response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    clear_auth_cookie(response)
    return response

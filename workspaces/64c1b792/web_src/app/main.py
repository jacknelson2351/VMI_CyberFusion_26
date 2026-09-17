import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from app.config import settings
from app.database import engine
from app.models import Base
from app.middleware import register_middleware
from app.routers import (
    auth_router,
    upload_router,
    images_router,
    albums_router,
    gallery_router,
    profile_router,
    api_router,
)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s", settings)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

    storage_path = Path(settings.STORAGE_PATH)
    storage_path.mkdir(parents=True, exist_ok=True)
    (storage_path / "originals").mkdir(exist_ok=True)
    (storage_path / "thumbs").mkdir(exist_ok=True)
    logger.info("Storage directories ready at %s", storage_path)

    yield

    await engine.dispose()
    logger.info("Shutdown complete")


app = FastAPI(
    title=settings.SITE_NAME,
    description="Image hosting platform",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)

register_middleware(app)

base_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(base_dir / "static")), name="static")

templates = Jinja2Templates(directory=str(base_dir / "templates"))
app.state.templates = templates

app.include_router(upload_router)
app.include_router(auth_router)
app.include_router(images_router)
app.include_router(albums_router)
app.include_router(gallery_router)
app.include_router(profile_router)
app.include_router(api_router)


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return HTMLResponse(content='{"detail":"Not found"}', status_code=404)
    return templates.TemplateResponse(
        "base.html",
        {"request": request, "settings": settings, "user": None},
        status_code=404,
    )

from app.routers.auth import router as auth_router
from app.routers.upload import router as upload_router
from app.routers.images import router as images_router
from app.routers.albums import router as albums_router
from app.routers.gallery import router as gallery_router
from app.routers.profile import router as profile_router
from app.routers.api import router as api_router

__all__ = [
    "auth_router", "upload_router", "images_router",
    "albums_router", "gallery_router", "profile_router", "api_router",
]

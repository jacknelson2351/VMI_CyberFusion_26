import io
import magic
from PIL import Image as PILImage, ExifTags
from app.config import settings



def is_valid_image(data):
    try:
        im = PILImage.open(io.BytesIO(data))
        im.verify()

        return True
    except Exception:
        return False


def validate_file_type(data: bytes, filename: str) -> str | None:
    mime = magic.from_buffer(data[:2048], mime=True)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in settings.allowed_extensions_list:
        return None
    return mime


def get_dimensions(data: bytes, mime: str) -> tuple[int | None, int | None]:
    if mime == "image/svg+xml":
        return None, None
    try:
        img = PILImage.open(io.BytesIO(data))
        return img.size
    except Exception:
        return None, None


def strip_exif(data: bytes, mime: str) -> bytes:
    if mime in ("image/svg+xml", "image/gif"):
        return data
    try:
        img = PILImage.open(io.BytesIO(data))
        img = _auto_orient(img)
        output = io.BytesIO()
        fmt = _pil_format(mime)
        img.save(output, format=fmt, quality=95)
        return output.getvalue()
    except Exception:
        return data


def generate_thumbnail(data: bytes, mime: str, size: int) -> bytes | None:
    if mime in ("image/svg+xml",):
        return None
    try:
        img = PILImage.open(io.BytesIO(data))
        img = _auto_orient(img)
        img.thumbnail((size, size), PILImage.Resampling.LANCZOS)
        if img.mode in ("RGBA", "LA", "P"):
            img = img.convert("RGBA")
        else:
            img = img.convert("RGB")
        output = io.BytesIO()
        img.save(output, format="WEBP", quality=85)
        return output.getvalue()
    except Exception:
        return None


def _auto_orient(img: PILImage.Image) -> PILImage.Image:
    try:
        exif = img.getexif()
        orientation_key = None
        for key, val in ExifTags.TAGS.items():
            if val == "Orientation":
                orientation_key = key
                break
        if orientation_key and orientation_key in exif:
            orientation = exif[orientation_key]
            rotations = {
                3: 180,
                6: 270,
                8: 90,
            }
            if orientation in rotations:
                img = img.rotate(rotations[orientation], expand=True)
    except Exception:
        pass
    return img


def _pil_format(mime: str) -> str:
    mapping = {
        "image/png": "PNG",
        "image/jpeg": "JPEG",
        "image/gif": "GIF",
        "image/webp": "WEBP",
        "image/bmp": "BMP",
        "image/tiff": "TIFF",
    }
    return mapping.get(mime, "PNG")

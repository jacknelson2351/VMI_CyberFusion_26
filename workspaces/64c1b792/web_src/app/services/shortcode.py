import secrets
import string

ALPHABET = string.ascii_letters + string.digits  # Base62


def generate(length: int = 8) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))

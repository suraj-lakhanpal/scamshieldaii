"""
ScamShield AI - Configuration
------------------------------
Central place for settings, limits, and CORS configuration.

IMPORTANT (security):
For local development we allow the typical Live Server / localhost origins.
Before deploying to production, replace ALLOWED_ORIGINS with the exact
domain(s) that will host your frontend. Never use "*" in production if you
plan to allow credentials, and always prefer an explicit allow-list.
"""

import os

# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------
SERVICE_NAME = "scamshield-backend"
APP_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# Local dev origins (VS Code Live Server default ports + plain file preview).
DEFAULT_DEV_ORIGINS = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:5501",
    "http://localhost:5501",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "null",  # some browsers send "null" origin when opening index.html directly
]

# Allow overriding via environment variable (comma separated) for production.
_env_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = (
    [o.strip() for o in _env_origins.split(",") if o.strip()]
    if _env_origins
    else DEFAULT_DEV_ORIGINS
)

# ---------------------------------------------------------------------------
# Limits (defensive design - avoid abuse / huge payloads)
# ---------------------------------------------------------------------------
MAX_URL_LENGTH = 2048
MAX_MESSAGE_LENGTH = 4000
MAX_MEDIA_TEXT_LENGTH = 4000
MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}

# ---------------------------------------------------------------------------
# Supported languages
# ---------------------------------------------------------------------------
SUPPORTED_LANGUAGES = {"en", "hi"}
DEFAULT_LANGUAGE = "en"


def normalize_language(language: str) -> str:
    """Return a supported language code, defaulting to English."""
    if not language:
        return DEFAULT_LANGUAGE
    language = language.strip().lower()
    return language if language in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE

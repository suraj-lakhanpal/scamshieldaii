"""
ScamShield AI - Backend Entry Point
--------------------------------------
FastAPI application exposing local, rule-based scam-detection heuristics.

Run with (from the `backend/` folder's parent, using --app-dir):
    py -m uvicorn app.main:app --reload --app-dir backend
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import (
    SERVICE_NAME,
    APP_VERSION,
    ALLOWED_ORIGINS,
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_IMAGE_MIME_TYPES,
    normalize_language,
)
from app.schemas import (
    LinkAnalysisRequest,
    MessageAnalysisRequest,
    AnalysisResponse,
    QRAnalysisResponse,
    MediaAnalysisResponse,
    HealthResponse,
    RootResponse,
)
from app.services.url_analyzer import analyze_url
from app.services.message_analyzer import analyze_message
from app.services.qr_analyzer import analyze_qr_bytes
from app.services.media_analyzer import analyze_media_text, analyze_media_image

app = FastAPI(
    title="ScamShield AI",
    description="A defensive, local heuristic scam-detection assistant.",
    version=APP_VERSION,
)
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Basic routes
# ---------------------------------------------------------------------------
@app.get("/", response_model=RootResponse)
def read_root():
    return RootResponse(
        project="ScamShield AI",
        description=(
            "A defensive, educational tool that uses local rule-based heuristics "
            "to highlight possible warning signs in links, messages, QR codes, "
            "and media. It never claims certainty and never contacts submitted URLs."
        ),
        version=APP_VERSION,
        disclaimer="This is a preliminary heuristic analysis tool, not a guarantee of safety.",
    )


@app.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(status="healthy", service=SERVICE_NAME)


# ---------------------------------------------------------------------------
# Link analysis
# ---------------------------------------------------------------------------
@app.post("/analyze-link", response_model=AnalysisResponse)
def analyze_link(payload: LinkAnalysisRequest):
    language = normalize_language(payload.language)
    result = analyze_url(payload.url, language)
    return AnalysisResponse(**result)


# ---------------------------------------------------------------------------
# Message analysis
# ---------------------------------------------------------------------------
@app.post("/analyze-message", response_model=AnalysisResponse)
def analyze_message_endpoint(payload: MessageAnalysisRequest):
    language = normalize_language(payload.language)
    result = analyze_message(payload.message, language)
    return AnalysisResponse(**result)


# ---------------------------------------------------------------------------
# QR analysis
# ---------------------------------------------------------------------------
@app.post("/analyze-qr", response_model=QRAnalysisResponse)
async def analyze_qr(file: UploadFile = File(...), language: str = Form("en")):
    language = normalize_language(language)

    if file.content_type not in ALLOWED_IMAGE_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{file.content_type}'. Please upload a PNG, JPEG, or WEBP image.",
        )

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)}MB.",
        )
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    result = analyze_qr_bytes(contents, language)
    return QRAnalysisResponse(**result)


# ---------------------------------------------------------------------------
# Media (experimental AI-content) analysis
# ---------------------------------------------------------------------------
@app.post("/analyze-media", response_model=MediaAnalysisResponse)
async def analyze_media(
    text: str = Form(None),
    language: str = Form("en"),
    file: UploadFile = File(None),
):
    language = normalize_language(language)

    if file is not None and file.filename:
        if file.content_type not in ALLOWED_IMAGE_MIME_TYPES:
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported file type '{file.content_type}'. Please upload a PNG, JPEG, or WEBP image.",
            )
        contents = await file.read()
        if len(contents) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)}MB.",
            )
        result = analyze_media_image(contents, language)
        return MediaAnalysisResponse(**result)

    if text and text.strip():
        result = analyze_media_text(text, language)
        return MediaAnalysisResponse(**result)

    raise HTTPException(status_code=400, detail="Please provide either 'text' or 'file' to analyze.")

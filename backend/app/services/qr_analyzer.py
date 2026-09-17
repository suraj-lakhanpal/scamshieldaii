"""
ScamShield AI - QR Analyzer
-----------------------------
Decodes a QR code from an uploaded image using OpenCV's built-in
QRCodeDetector (pure local processing, no external service, no system
dependency beyond the opencv-python-headless package).

Safety rules enforced here:
- Images are processed only in memory (a temp file is used only because
  OpenCV's classic API prefers a path in some environments; it is deleted
  immediately after decoding).
- Decoded content is NEVER executed or opened.
- If the decoded content is a URL, it is only analyzed as a string via the
  URL analyzer - never fetched.
"""

import os
import tempfile
import uuid

from app.config import normalize_language
from app.services.url_analyzer import analyze_url

try:
    import cv2  # opencv-python-headless
    import numpy as np
    OPENCV_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dependency missing
    OPENCV_AVAILABLE = False

TEXT = {
    "en": {
        "unavailable": "QR decoding is not available on this server because the OpenCV package is not installed. Install 'opencv-python-headless' to enable this feature.",
        "decode_failed": "No QR code could be detected in this image. Try a clearer, well-lit photo of just the QR code.",
        "decoded_url": "A link was found inside the QR code. It has been analyzed below without being opened.",
        "decoded_text": "Text was found inside the QR code. It does not appear to be a link.",
        "bad_image": "The uploaded file could not be read as an image.",
    },
    "hi": {
        "unavailable": "इस सर्वर पर QR डिकोडिंग उपलब्ध नहीं है क्योंकि OpenCV पैकेज इंस्टॉल नहीं है। इसे सक्षम करने के लिए 'opencv-python-headless' इंस्टॉल करें।",
        "decode_failed": "इस छवि में कोई QR कोड नहीं मिला। कृपया केवल QR कोड की एक स्पष्ट, अच्छी रोशनी वाली तस्वीर आज़माएं।",
        "decoded_url": "QR कोड के अंदर एक लिंक मिला। इसे बिना खोले नीचे विश्लेषित किया गया है।",
        "decoded_text": "QR कोड के अंदर टेक्स्ट मिला। यह किसी लिंक जैसा नहीं लगता।",
        "bad_image": "अपलोड की गई फ़ाइल को छवि के रूप में नहीं पढ़ा जा सका।",
    },
}


def _looks_like_url(content: str) -> bool:
    lowered = content.strip().lower()
    return lowered.startswith("http://") or lowered.startswith("https://") or lowered.startswith("www.")


def analyze_qr_bytes(image_bytes: bytes, language: str = "en") -> dict:
    """
    Decode a QR code from raw image bytes. Returns a dict describing the
    outcome. Never executes or opens decoded content.
    """
    language = normalize_language(language)

    if not OPENCV_AVAILABLE:
        return {
            "decoded": False,
            "raw_content": None,
            "content_type": "none",
            "url_analysis": None,
            "message": TEXT[language]["unavailable"],
        }

    tmp_path = None
    try:
        # Decode directly from memory buffer - no permanent file written.
        np_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(np_array, cv2.IMREAD_COLOR)

        if image is None:
            return {
                "decoded": False,
                "raw_content": None,
                "content_type": "none",
                "url_analysis": None,
                "message": TEXT[language]["bad_image"],
            }

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(image)

        # Some real-world photos/screenshots have little or no quiet zone
        # (white margin) around the QR code, or the code is quite small,
        # which can make detection fail. As a local, harmless fallback,
        # retry once with an added white border and a larger scale.
        if not data:
            bordered = cv2.copyMakeBorder(
                image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=(255, 255, 255)
            )
            scaled = cv2.resize(
                bordered, None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST
            )
            data, points, _ = detector.detectAndDecode(scaled)

        if not data:
            return {
                "decoded": False,
                "raw_content": None,
                "content_type": "none",
                "url_analysis": None,
                "message": TEXT[language]["decode_failed"],
            }

        if _looks_like_url(data):
            url_result = analyze_url(data, language)
            return {
                "decoded": True,
                "raw_content": data,
                "content_type": "url",
                "url_analysis": url_result,
                "message": TEXT[language]["decoded_url"],
            }

        return {
            "decoded": True,
            "raw_content": data,
            "content_type": "text",
            "url_analysis": None,
            "message": TEXT[language]["decoded_text"],
        }

    finally:
        # Nothing is written to disk in this implementation, but if a future
        # version needs a temp file, ensure cleanup happens here.
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

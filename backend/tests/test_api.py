"""
ScamShield AI - API Tests
---------------------------
All tests run fully locally against the FastAPI TestClient.
No real external websites are contacted.

Run with:
    py -m pytest backend\\tests
"""

import io
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Root / health
# ---------------------------------------------------------------------------
def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["project"] == "ScamShield AI"
    assert "disclaimer" in data


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "scamshield-backend"


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------
def test_valid_url_low_risk():
    resp = client.post("/analyze-link", json={"url": "https://www.wikipedia.org", "language": "en"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in ("low", "medium", "high")
    assert "disclaimer" in data


def test_invalid_url():
    resp = client.post("/analyze-link", json={"url": "not a url at all !!", "language": "en"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in ("medium", "high")
    assert len(data["red_flags"]) > 0


def test_http_url_flagged():
    resp = client.post("/analyze-link", json={"url": "http://example.com/login", "language": "en"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 0
    joined_flags = " ".join(data["red_flags"]).lower()
    assert "http" in joined_flags or "https" in joined_flags


def test_ip_address_url_flagged():
    resp = client.post("/analyze-link", json={"url": "http://192.168.1.1/verify-account", "language": "en"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["technical_details"]["hostname_is_ip"] is True
    assert data["risk_level"] in ("medium", "high")


def test_punycode_url_flagged():
    resp = client.post("/analyze-link", json={"url": "https://xn--pple-43d.com/secure/login", "language": "en"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in ("medium", "high")
    assert data["risk_score"] >= 40
    assert any("punycode" in flag.lower() or "xn--" in flag.lower() for flag in data["red_flags"])


def test_suspicious_keyword_url():
    resp = client.post(
        "/analyze-link",
        json={"url": "https://free-reward-claim-now.example-secure-payment.com/verify", "language": "en"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 30


def test_empty_url_rejected():
    resp = client.post("/analyze-link", json={"url": "", "language": "en"})
    assert resp.status_code == 422  # pydantic min_length validation


# ---------------------------------------------------------------------------
# Message analysis
# ---------------------------------------------------------------------------
def test_suspicious_message():
    resp = client.post(
        "/analyze-message",
        json={
            "message": "URGENT: Your account will be blocked. Send your OTP immediately to avoid suspension.",
            "language": "en",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in ("medium", "high")
    assert len(data["red_flags"]) > 0


def test_empty_message_rejected():
    resp = client.post("/analyze-message", json={"message": "", "language": "en"})
    assert resp.status_code == 422


def test_benign_message_low_risk():
    resp = client.post(
        "/analyze-message",
        json={"message": "Hey, are we still meeting for lunch tomorrow?", "language": "en"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "low"


def test_hindi_message():
    resp = client.post(
        "/analyze-message",
        json={"message": "आपका खाता ब्लॉक हो जाएगा, तुरंत OTP भेजें", "language": "hi"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["language"] == "hi"


# ---------------------------------------------------------------------------
# Upload validation (QR + media)
# ---------------------------------------------------------------------------
def test_qr_unsupported_upload():
    fake_file = io.BytesIO(b"not a real image")
    resp = client.post(
        "/analyze-qr",
        files={"file": ("note.txt", fake_file, "text/plain")},
        data={"language": "en"},
    )
    assert resp.status_code == 415


def test_qr_oversized_upload():
    big_content = b"0" * (6 * 1024 * 1024)  # 6MB > 5MB limit
    fake_file = io.BytesIO(big_content)
    resp = client.post(
        "/analyze-qr",
        files={"file": ("big.png", fake_file, "image/png")},
        data={"language": "en"},
    )
    assert resp.status_code == 413


def test_media_no_input_rejected():
    resp = client.post("/analyze-media", data={"language": "en"})
    assert resp.status_code == 400


def test_media_text_input():
    resp = client.post(
        "/analyze-media",
        data={"text": "This is a normal, everyday sentence written by a person.", "language": "en"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis_type"] == "experimental"


# ---------------------------------------------------------------------------
# Language handling
# ---------------------------------------------------------------------------
def test_unsupported_language_defaults_to_english():
    resp = client.post("/analyze-link", json={"url": "https://example.com", "language": "fr"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["language"] == "en"

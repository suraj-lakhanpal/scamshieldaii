"""
ScamShield AI - Media Analyzer (EXPERIMENTAL)
------------------------------------------------
This module provides a clearly-labeled, EXPERIMENTAL heuristic check for
text or images. It does NOT reliably detect AI-generated content, and it
never claims to. It only surfaces transparent, explainable signals.
"""

import io
import re
from collections import Counter

from app.config import normalize_language

try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    PIL_AVAILABLE = False

TEXT = {
    "en": {
        "no_input": "Please provide either text or an image to analyze.",
        "text_explanation": "This experimental check looks only at surface-level writing patterns (repetition, generic phrasing, formatting). It cannot reliably determine whether text was AI-generated.",
        "image_explanation": "This experimental check looks only at basic image metadata and simple properties. It cannot reliably determine whether an image was AI-generated.",
        "sig_repetitive": "Repeated words or phrases were detected.",
        "sig_generic": "The wording uses very generic, template-like phrasing.",
        "sig_formatting": "Excessive or unusual formatting (e.g. many exclamation marks or emojis) was detected.",
        "sig_short": "The text is too short for these signals to be meaningful.",
        "sig_no_exif": "No camera/creation metadata (EXIF) was found. This is common for both AI-generated images and images shared through messaging apps that strip metadata.",
        "sig_has_exif": "Camera/creation metadata (EXIF) was found, which is more commonly seen in camera-captured photos.",
        "result_inconclusive": "inconclusive",
    },
    "hi": {
        "no_input": "कृपया विश्लेषण के लिए टेक्स्ट या छवि प्रदान करें।",
        "text_explanation": "यह प्रायोगिक जांच केवल सतही लेखन पैटर्न (दोहराव, सामान्य वाक्यांश, फ़ॉर्मेटिंग) को देखती है। यह विश्वसनीय रूप से यह निर्धारित नहीं कर सकती कि टेक्स्ट AI-जनित है या नहीं।",
        "image_explanation": "यह प्रायोगिक जांच केवल बुनियादी छवि मेटाडेटा और सरल गुणों को देखती है। यह विश्वसनीय रूप से यह निर्धारित नहीं कर सकती कि छवि AI-जनित है या नहीं।",
        "sig_repetitive": "दोहराए गए शब्द या वाक्यांश पाए गए।",
        "sig_generic": "शब्दों में बहुत सामान्य, टेम्पलेट जैसी भाषा है।",
        "sig_formatting": "अत्यधिक या असामान्य फ़ॉर्मेटिंग (जैसे कई विस्मयादिबोधक चिन्ह या इमोजी) पाई गई।",
        "sig_short": "इन संकेतों के सार्थक होने के लिए टेक्स्ट बहुत छोटा है।",
        "sig_no_exif": "कोई कैमरा/निर्माण मेटाडेटा (EXIF) नहीं मिला। यह AI-जनित छवियों और मैसेजिंग ऐप के ज़रिए साझा की गई छवियों दोनों में आम है।",
        "sig_has_exif": "कैमरा/निर्माण मेटाडेटा (EXIF) मिला, जो आमतौर पर कैमरे से खींची गई तस्वीरों में देखा जाता है।",
        "result_inconclusive": "अनिर्णायक",
    },
}

GENERIC_PHRASES = [
    "in today's world", "in conclusion", "it is important to note",
    "as an ai", "overall, it is clear", "in summary",
]


def _analyze_text_signals(text: str, language: str) -> list:
    signals = []
    words = re.findall(r"\w+", text.lower())

    if len(words) < 15:
        signals.append(TEXT[language]["sig_short"])
        return signals

    counts = Counter(words)
    most_common_word, most_common_count = counts.most_common(1)[0]
    if most_common_count / max(len(words), 1) > 0.12:
        signals.append(TEXT[language]["sig_repetitive"])

    lowered = text.lower()
    if any(phrase in lowered for phrase in GENERIC_PHRASES):
        signals.append(TEXT[language]["sig_generic"])

    exclamations = text.count("!")
    if exclamations > 5 or len(re.findall(r"[\U0001F300-\U0001FAFF]", text)) > 5:
        signals.append(TEXT[language]["sig_formatting"])

    return signals


def analyze_media_text(text: str, language: str = "en") -> dict:
    language = normalize_language(language)
    text = (text or "").strip()

    if not text:
        return {
            "analysis_type": "experimental",
            "result": TEXT[language]["result_inconclusive"],
            "signals": [],
            "explanation": TEXT[language]["no_input"],
            "disclaimer": "AI-generated-content detection is uncertain and this result is not proof.",
        }

    signals = _analyze_text_signals(text, language)

    return {
        "analysis_type": "experimental",
        "result": TEXT[language]["result_inconclusive"],
        "signals": signals,
        "explanation": TEXT[language]["text_explanation"],
        "disclaimer": "AI-generated-content detection is uncertain and this result is not proof.",
    }


def analyze_media_image(image_bytes: bytes, language: str = "en") -> dict:
    language = normalize_language(language)

    if not PIL_AVAILABLE:
        return {
            "analysis_type": "experimental",
            "result": TEXT[language]["result_inconclusive"],
            "signals": [],
            "explanation": "Image analysis is not available on this server because the Pillow package is not installed.",
            "disclaimer": "AI-generated-content detection is uncertain and this result is not proof.",
        }

    signals = []
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.verify()
        # Re-open because verify() invalidates the image object for further use.
        image = Image.open(io.BytesIO(image_bytes))
        exif_data = image.getexif()
        if exif_data and len(exif_data) > 0:
            signals.append(TEXT[language]["sig_has_exif"])
        else:
            signals.append(TEXT[language]["sig_no_exif"])
    except Exception:
        return {
            "analysis_type": "experimental",
            "result": TEXT[language]["result_inconclusive"],
            "signals": [],
            "explanation": TEXT[language]["no_input"],
            "disclaimer": "AI-generated-content detection is uncertain and this result is not proof.",
        }

    return {
        "analysis_type": "experimental",
        "result": TEXT[language]["result_inconclusive"],
        "signals": signals,
        "explanation": TEXT[language]["image_explanation"],
        "disclaimer": "AI-generated-content detection is uncertain and this result is not proof.",
    }

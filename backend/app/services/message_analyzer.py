"""
ScamShield AI - Message Analyzer
----------------------------------
Local, rule-based heuristic analysis of a pasted message (SMS/WhatsApp/email
style text). No message content is logged or stored permanently.
"""

import re

from app.config import normalize_language
from app.services.url_analyzer import analyze_url

# ---------------------------------------------------------------------------
# Pattern groups. Each maps to a (english_flag, hindi_flag, weight) tuple.
# Patterns are intentionally simple keyword/regex heuristics.
# ---------------------------------------------------------------------------
PATTERN_GROUPS = [
    {
        "id": "urgency",
        "patterns": [r"\burgent\b", r"immediately", r"right now", r"act now", r"within \d+ (hour|minute)"],
        "weight": 12,
    },
    {
        "id": "threat",
        "patterns": [r"account.*(blocked|suspended|closed)", r"legal action", r"will be (blocked|banned|terminated)", r"penalty"],
        "weight": 18,
    },
    {
        "id": "otp_request",
        "patterns": [r"\botp\b", r"one[- ]time password", r"verification code"],
        "weight": 22,
    },
    {
        "id": "password_request",
        "patterns": [r"\bpassword\b", r"\bpin\b", r"cvv"],
        "weight": 22,
    },
    {
        "id": "banking_request",
        "patterns": [r"bank account", r"account number", r"ifsc", r"upi id", r"debit card", r"credit card", r"net banking"],
        "weight": 20,
    },
    {
        "id": "fake_reward",
        "patterns": [r"you have won", r"you\'?ve won", r"lucky draw", r"lottery", r"cashback of", r"claim your (prize|reward|gift)"],
        "weight": 15,
    },
    {
        "id": "impersonation",
        "patterns": [r"(bank|income tax|customs|police|courier|delivery) (department|officer|team) will", r"this is (your bank|the bank|customs)"],
        "weight": 15,
    },
    {
        "id": "apk_request",
        "patterns": [r"\.apk\b", r"install (this )?app", r"download (this )?app to"],
        "weight": 20,
    },
    {
        "id": "click_link",
        "patterns": [r"click (the|this|below)?\s*link", r"click here", r"tap (the|this) link"],
        "weight": 10,
    },
    {
        "id": "secrecy",
        "patterns": [r"do not tell", r"keep this (confidential|secret)", r"don\'?t share this with anyone"],
        "weight": 15,
    },
    {
        "id": "fear_pressure",
        "patterns": [r"failure to (respond|comply)", r"final (notice|warning)", r"last chance"],
        "weight": 12,
    },
]

URL_REGEX = re.compile(r"(https?://\S+|www\.\S+|\b[a-zA-Z0-9-]+\.(?:com|in|net|org|xyz|info|link|click)\b\S*)")

TEXT = {
    "en": {
        "flag_urgency": "The message uses urgency to pressure quick action.",
        "flag_threat": "The message threatens negative consequences (blocking, legal action, etc).",
        "flag_otp_request": "The message references an OTP or verification code - never share these.",
        "flag_password_request": "The message references a password, PIN, or CVV - never share these.",
        "flag_banking_request": "The message asks for banking or payment details.",
        "flag_fake_reward": "The message offers an unexpected reward, prize, or lottery win.",
        "flag_impersonation": "The message may be impersonating an official organization.",
        "flag_apk_request": "The message asks you to install an app or APK file from outside an official app store.",
        "flag_click_link": "The message pressures you to click a link.",
        "flag_secrecy": "The message asks you to keep this secret, a common manipulation tactic.",
        "flag_fear_pressure": "The message uses fear-based or last-chance style pressure.",
        "flag_link_present": "The message contains a link, which was analyzed separately below.",
        "empty": "The message is empty.",
        "summary_low": "Preliminary heuristic analysis found few or no common scam patterns. This is not a guarantee that the message is safe.",
        "summary_medium": "Preliminary heuristic analysis found some possible warning signs commonly seen in scam messages. Verify through an official source before acting.",
        "summary_high": "Preliminary heuristic analysis found several warning signs strongly associated with scam or phishing messages. This is not a guarantee of fraud, but strong caution is advised.",
        "advice": [
            "Never share OTPs, passwords, PINs, or card details with anyone.",
            "Contact the organization using an officially published phone number or app, not a number in this message.",
            "Do not install apps from links sent in messages.",
            "Slow down - legitimate organizations rarely demand instant action.",
            "If in doubt, report the message to your telecom provider or the relevant platform.",
        ],
    },
    "hi": {
        "flag_urgency": "यह संदेश जल्दी कार्रवाई के लिए दबाव बनाने हेतु तात्कालिकता का उपयोग करता है।",
        "flag_threat": "यह संदेश नकारात्मक परिणामों (ब्लॉक होना, कानूनी कार्रवाई आदि) की धमकी देता है।",
        "flag_otp_request": "यह संदेश OTP या सत्यापन कोड का ज़िक्र करता है - इसे कभी साझा न करें।",
        "flag_password_request": "यह संदेश पासवर्ड, पिन या CVV का ज़िक्र करता है - इसे कभी साझा न करें।",
        "flag_banking_request": "यह संदेश बैंकिंग या भुगतान जानकारी मांगता है।",
        "flag_fake_reward": "यह संदेश एक अप्रत्याशित इनाम, पुरस्कार या लॉटरी जीतने का दावा करता है।",
        "flag_impersonation": "यह संदेश किसी आधिकारिक संस्था की नकल कर सकता है।",
        "flag_apk_request": "यह संदेश आपको किसी अनाधिकारिक स्रोत से ऐप या APK फ़ाइल इंस्टॉल करने के लिए कहता है।",
        "flag_click_link": "यह संदेश लिंक पर क्लिक करने के लिए दबाव डालता है।",
        "flag_secrecy": "यह संदेश इसे गुप्त रखने के लिए कहता है, जो एक आम हेरफेर की चाल है।",
        "flag_fear_pressure": "यह संदेश डर या 'आखिरी मौका' जैसी शैली का उपयोग करता है।",
        "flag_link_present": "इस संदेश में एक लिंक है, जिसका नीचे अलग से विश्लेषण किया गया है।",
        "empty": "संदेश खाली है।",
        "summary_low": "प्रारंभिक ह्यूरिस्टिक विश्लेषण में कोई या बहुत कम सामान्य स्कैम पैटर्न मिले। यह गारंटी नहीं है कि संदेश सुरक्षित है।",
        "summary_medium": "प्रारंभिक ह्यूरिस्टिक विश्लेषण में स्कैम संदेशों में आमतौर पर पाए जाने वाले कुछ चेतावनी संकेत मिले। कार्रवाई करने से पहले किसी आधिकारिक स्रोत से पुष्टि करें।",
        "summary_high": "प्रारंभिक ह्यूरिस्टिक विश्लेषण में स्कैम या फ़िशिंग संदेशों से जुड़े कई चेतावनी संकेत मिले। यह धोखाधड़ी की गारंटी नहीं है, लेकिन अत्यधिक सावधानी बरतने की सलाह दी जाती है।",
        "advice": [
            "किसी के साथ भी OTP, पासवर्ड, पिन या कार्ड की जानकारी साझा न करें।",
            "संस्था से संपर्क करने के लिए आधिकारिक रूप से प्रकाशित फ़ोन नंबर या ऐप का उपयोग करें, इस संदेश के नंबर का नहीं।",
            "संदेशों में भेजे गए लिंक से ऐप इंस्टॉल न करें।",
            "जल्दबाज़ी न करें - असली संस्थाएं शायद ही कभी तुरंत कार्रवाई की मांग करती हैं।",
            "संदेह होने पर, इसकी रिपोर्ट अपने टेलीकॉम प्रदाता या संबंधित प्लेटफ़ॉर्म को करें।",
        ],
    },
}


def _risk_level(score: int) -> str:
    if score <= 29:
        return "low"
    if score <= 69:
        return "medium"
    return "high"


def analyze_message(message: str, language: str = "en") -> dict:
    """Analyze a message using local keyword/regex heuristics only."""
    language = normalize_language(language)
    text = (message or "").strip()

    if not text:
        return {
            "original_input": message or "",
            "normalized_input": None,
            "language": language,
            "risk_level": "medium",
            "risk_score": 50,
            "summary": TEXT[language]["empty"],
            "red_flags": [TEXT[language]["empty"]],
            "safety_advice": list(TEXT[language]["advice"]),
            "technical_details": {"valid": False},
            "disclaimer": "This is a preliminary heuristic analysis, not a guarantee.",
        }

    lowered = text.lower()
    red_flags = []
    score = 0
    matched_ids = []

    for group in PATTERN_GROUPS:
        for pattern in group["patterns"]:
            if re.search(pattern, lowered):
                matched_ids.append(group["id"])
                red_flags.append(TEXT[language][f"flag_{group['id']}"])
                score += group["weight"]
                break  # only count each group once

    # Detect an embedded link (do not fetch it - just note it and analyze
    # it the same way the URL scanner would, purely as a string).
    url_match = URL_REGEX.search(text)
    embedded_url_result = None
    if url_match:
        red_flags.append(TEXT[language]["flag_link_present"])
        score += 6
        embedded_url_result = analyze_url(url_match.group(0), language)

    score = max(0, min(100, score))
    risk_level = _risk_level(score)

    if risk_level == "low":
        summary = TEXT[language]["summary_low"]
    elif risk_level == "medium":
        summary = TEXT[language]["summary_medium"]
    else:
        summary = TEXT[language]["summary_high"]

    technical_details = {
        "matched_pattern_groups": matched_ids,
        "message_length": len(text),
        "embedded_link_found": bool(url_match),
    }
    if embedded_url_result:
        technical_details["embedded_link_analysis"] = embedded_url_result

    return {
        # NOTE: we deliberately avoid echoing back the full raw message into
        # any persistent store; this dict is only ever returned in the HTTP
        # response and is not logged or written to disk.
        "original_input": text[:200] + ("..." if len(text) > 200 else ""),
        "normalized_input": None,
        "language": language,
        "risk_level": risk_level,
        "risk_score": score,
        "summary": summary,
        "red_flags": red_flags,
        "safety_advice": list(TEXT[language]["advice"]),
        "technical_details": technical_details,
        "disclaimer": "This is a preliminary heuristic analysis, not a guarantee.",
    }

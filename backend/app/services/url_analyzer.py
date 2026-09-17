"""
ScamShield AI - URL Analyzer
-----------------------------
Local, rule-based heuristic analysis of a URL. No outbound network requests
are ever made to the submitted URL. This module only inspects the URL
string itself (scheme, hostname, path, query, etc.).

The score is a simple, explainable heuristic - NOT a scientifically
validated probability of maliciousness.
"""

import re
from urllib.parse import urlparse, unquote

from app.config import MAX_URL_LENGTH, normalize_language

# ---------------------------------------------------------------------------
# Static reference data
# ---------------------------------------------------------------------------
SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "payment", "wallet",
    "password", "otp", "reward", "prize", "urgent", "claim",
    "update", "confirm", "bonus", "gift", "winner", "unlock",
]

KNOWN_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
    "tiny.cc", "rb.gy", "shorturl.at",
}

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".apk", ".scr", ".bat", ".cmd", ".msi", ".jar", ".vbs",
)

IP_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

# A reasonably strict hostname pattern: labels of letters/digits/hyphens,
# separated by dots. Rejects spaces and most punctuation that indicates the
# input isn't a real hostname at all.
HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

MAX_REASONABLE_HOSTNAME_LENGTH = 253
MAX_REASONABLE_SUBDOMAINS = 3
LONG_URL_THRESHOLD = 90
MANY_QUERY_PARAMS_THRESHOLD = 5


# ---------------------------------------------------------------------------
# Bilingual text templates
# ---------------------------------------------------------------------------
TEXT = {
    "en": {
        "empty": "The URL is empty.",
        "too_long": "The URL is unusually long, which is often used to hide the real destination.",
        "bad_scheme": "Only http:// and https:// links can be analyzed.",
        "invalid": "This does not look like a syntactically valid URL.",
        "credentials": "The URL contains embedded login credentials (user:pass@host), a common phishing trick.",
        "no_hostname": "No hostname could be found in this URL.",
        "hostname_too_long": "The hostname is unusually long.",
        "http_not_https": "The link uses HTTP instead of the more secure HTTPS.",
        "ip_hostname": "The link uses a raw IP address instead of a domain name.",
        "punycode": "The domain uses punycode (xn--), sometimes used to imitate a trusted brand with look-alike characters.",
        "suspicious_word": "The link contains a sensitive keyword ('{word}') often used in scam or phishing links.",
        "many_subdomains": "The link has an unusually high number of subdomains.",
        "long_url": "The overall URL length is unusually long.",
        "many_query_params": "The link has many query parameters, which can be used to obscure tracking or redirect data.",
        "suspicious_extension": "The link points to a file type ('{ext}') that can be used to distribute unwanted software.",
        "shortener": "The link uses a known URL-shortening service, which can hide the real destination.",
        "encoded_chars": "The link contains encoded characters that may be hiding its real content.",
        "at_symbol": "The link contains an '@' symbol, a classic trick to disguise the real destination.",
        "unusual_structure": "The hostname structure looks unusual (e.g. excessive hyphens or digits).",
        "summary_low": "Preliminary heuristic analysis found few or no common warning signs. This is not a guarantee of safety.",
        "summary_medium": "Preliminary heuristic analysis found some possible warning signs. Please proceed carefully and verify through an official source.",
        "summary_high": "Preliminary heuristic analysis found several possible warning signs commonly associated with scam or phishing links. This is not a guarantee that the link is fraudulent, but caution is strongly advised.",
        "advice": [
            "Do not enter passwords, OTPs, or card details on this page.",
            "Type the official website address directly into your browser instead of clicking the link.",
            "Verify through an official source such as the organization's known phone number or app.",
            "When in doubt, do not click - ask someone you trust or report it.",
        ],
    },
    "hi": {
        "empty": "URL खाली है।",
        "too_long": "यह URL असामान्य रूप से लंबा है, जो अक्सर असली गंतव्य छिपाने के लिए इस्तेमाल होता है।",
        "bad_scheme": "केवल http:// और https:// लिंक का विश्लेषण किया जा सकता है।",
        "invalid": "यह एक सही ढंग से बना हुआ URL नहीं लगता।",
        "credentials": "इस URL में लॉगिन जानकारी (user:pass@host) छिपी है, जो फ़िशिंग की एक आम चाल है।",
        "no_hostname": "इस URL में कोई होस्टनेम नहीं मिला।",
        "hostname_too_long": "होस्टनेम असामान्य रूप से लंबा है।",
        "http_not_https": "यह लिंक सुरक्षित HTTPS के बजाय HTTP का उपयोग करता है।",
        "ip_hostname": "यह लिंक डोमेन नाम के बजाय सीधे IP पते का उपयोग करता है।",
        "punycode": "इस डोमेन में punycode (xn--) है, जिसका उपयोग कभी-कभी किसी भरोसेमंद ब्रांड की नकल करने के लिए किया जाता है।",
        "suspicious_word": "इस लिंक में एक संवेदनशील शब्द ('{word}') है जो अक्सर स्कैम या फ़िशिंग लिंक में उपयोग होता है।",
        "many_subdomains": "इस लिंक में असामान्य रूप से कई सब-डोमेन हैं।",
        "long_url": "इस URL की कुल लंबाई असामान्य रूप से अधिक है।",
        "many_query_params": "इस लिंक में कई क्वेरी पैरामीटर हैं, जिनका उपयोग ट्रैकिंग या रीडायरेक्ट डेटा छिपाने के लिए किया जा सकता है।",
        "suspicious_extension": "यह लिंक एक फ़ाइल प्रकार ('{ext}') की ओर इशारा करता है जिसका उपयोग अवांछित सॉफ़्टवेयर फैलाने के लिए किया जा सकता है।",
        "shortener": "यह लिंक एक जाने-माने URL-छोटा करने वाली सेवा का उपयोग करता है, जो असली गंतव्य छिपा सकती है।",
        "encoded_chars": "इस लिंक में एन्कोडेड वर्ण हैं जो इसकी असली सामग्री छिपा सकते हैं।",
        "at_symbol": "इस लिंक में '@' चिन्ह है, जो असली गंतव्य छिपाने की एक पुरानी चाल है।",
        "unusual_structure": "होस्टनेम की बनावट असामान्य लगती है (जैसे बहुत सारे हाइफ़न या अंक)।",
        "summary_low": "प्रारंभिक ह्यूरिस्टिक विश्लेषण में कोई या बहुत कम सामान्य चेतावनी संकेत मिले। यह सुरक्षा की गारंटी नहीं है।",
        "summary_medium": "प्रारंभिक ह्यूरिस्टिक विश्लेषण में कुछ संभावित चेतावनी संकेत मिले। कृपया सावधानी बरतें और किसी आधिकारिक स्रोत से पुष्टि करें।",
        "summary_high": "प्रारंभिक ह्यूरिस्टिक विश्लेषण में स्कैम या फ़िशिंग लिंक से जुड़े कई संभावित चेतावनी संकेत मिले। यह गारंटी नहीं है कि लिंक धोखाधड़ी वाला है, लेकिन सावधानी बरतने की सलाह दी जाती है।",
        "advice": [
            "इस पेज पर पासवर्ड, OTP या कार्ड की जानकारी न डालें।",
            "लिंक पर क्लिक करने के बजाय आधिकारिक वेबसाइट का पता सीधे ब्राउज़र में टाइप करें।",
            "किसी आधिकारिक स्रोत जैसे संस्था के जाने-माने फ़ोन नंबर या ऐप से पुष्टि करें।",
            "संदेह होने पर क्लिक न करें - किसी भरोसेमंद व्यक्ति से पूछें या इसकी रिपोर्ट करें।",
        ],
    },
}


def _t(language: str, key: str) -> str:
    return TEXT[language][key]


def _risk_level(score: int) -> str:
    if score <= 29:
        return "low"
    if score <= 69:
        return "medium"
    return "high"


def analyze_url(raw_url: str, language: str = "en") -> dict:
    """
    Analyze a URL using local, static heuristics only.
    Never makes an outbound request to the submitted URL.
    """
    language = normalize_language(language)
    red_flags = []
    score = 0
    technical_details = {}

    original_url = raw_url or ""
    stripped = original_url.strip()

    # --- Basic validation -------------------------------------------------
    if not stripped:
        return _error_result(original_url, language, _t(language, "empty"))

    if len(stripped) > MAX_URL_LENGTH:
        return _error_result(original_url, language, _t(language, "too_long"))

    # Add a scheme if the user forgot one, so urlparse works predictably.
    candidate = stripped
    if "://" not in candidate:
        candidate = "http://" + candidate

    try:
        parsed = urlparse(candidate)
    except Exception:
        return _error_result(original_url, language, _t(language, "invalid"))

    if parsed.scheme not in ("http", "https"):
        return _error_result(original_url, language, _t(language, "bad_scheme"))

    hostname = parsed.hostname or ""
    if not hostname:
        return _error_result(original_url, language, _t(language, "no_hostname"))

    if len(hostname) > MAX_REASONABLE_HOSTNAME_LENGTH:
        return _error_result(original_url, language, _t(language, "hostname_too_long"))

    is_ip_candidate = bool(IP_PATTERN.match(hostname))
    if not is_ip_candidate and not HOSTNAME_PATTERN.match(hostname):
        return _error_result(original_url, language, _t(language, "invalid"))

    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        red_flags.append(_t(language, "credentials"))
        score += 25
        technical_details["contains_credentials"] = True

    normalized_url = parsed.geturl()

    # --- Heuristic checks ---------------------------------------------------
    if parsed.scheme == "http":
        red_flags.append(_t(language, "http_not_https"))
        score += 15

    is_ip = bool(IP_PATTERN.match(hostname))
    technical_details["hostname_is_ip"] = is_ip
    if is_ip:
        red_flags.append(_t(language, "ip_hostname"))
        score += 20

    if "xn--" in hostname.lower():
        red_flags.append(_t(language, "punycode"))
        score += 30

    full_text_for_words = f"{hostname} {parsed.path} {parsed.query}".lower()
    matched_words = [w for w in SUSPICIOUS_WORDS if w in full_text_for_words]
    technical_details["matched_keywords"] = matched_words
    for word in matched_words[:5]:
        red_flags.append(_t(language, "suspicious_word").format(word=word))
        score += 8

    subdomain_count = max(0, hostname.count(".") - 1) if not is_ip else 0
    technical_details["subdomain_count"] = subdomain_count
    if subdomain_count > MAX_REASONABLE_SUBDOMAINS:
        red_flags.append(_t(language, "many_subdomains"))
        score += 10

    technical_details["url_length"] = len(stripped)
    if len(stripped) > LONG_URL_THRESHOLD:
        red_flags.append(_t(language, "long_url"))
        score += 10

    query_param_count = len([p for p in parsed.query.split("&") if p]) if parsed.query else 0
    technical_details["query_param_count"] = query_param_count
    if query_param_count > MANY_QUERY_PARAMS_THRESHOLD:
        red_flags.append(_t(language, "many_query_params"))
        score += 8

    path_lower = parsed.path.lower()
    matched_ext = next((ext for ext in SUSPICIOUS_EXTENSIONS if path_lower.endswith(ext)), None)
    if matched_ext:
        red_flags.append(_t(language, "suspicious_extension").format(ext=matched_ext))
        score += 20

    registrable_domain = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
    technical_details["registrable_domain_guess"] = registrable_domain
    if registrable_domain in KNOWN_SHORTENER_DOMAINS or hostname in KNOWN_SHORTENER_DOMAINS:
        red_flags.append(_t(language, "shortener"))
        score += 10

    if "%" in stripped:
        try:
            decoded = unquote(stripped)
            if decoded != stripped:
                red_flags.append(_t(language, "encoded_chars"))
                score += 8
        except Exception:
            pass

    if "@" in stripped and not (parsed.username or parsed.password):
        # '@' appears somewhere outside the recognized credential position
        red_flags.append(_t(language, "at_symbol"))
        score += 10

    hyphen_count = hostname.count("-")
    digit_count = sum(ch.isdigit() for ch in hostname)
    if hyphen_count >= 3 or digit_count >= 5:
        red_flags.append(_t(language, "unusual_structure"))
        score += 8

    score = max(0, min(100, score))
    risk_level = _risk_level(score)

    if risk_level == "low":
        summary = _t(language, "summary_low")
    elif risk_level == "medium":
        summary = _t(language, "summary_medium")
    else:
        summary = _t(language, "summary_high")

    return {
        "original_input": original_url,
        "normalized_input": normalized_url,
        "language": language,
        "risk_level": risk_level,
        "risk_score": score,
        "summary": summary,
        "red_flags": red_flags,
        "safety_advice": list(TEXT[language]["advice"]),
        "technical_details": technical_details,
        "disclaimer": "This is a preliminary heuristic analysis, not a guarantee.",
    }


def _error_result(original_url: str, language: str, reason: str) -> dict:
    """Used when the URL cannot be parsed/validated at all."""
    return {
        "original_input": original_url,
        "normalized_input": None,
        "language": language,
        "risk_level": "medium",
        "risk_score": 50,
        "summary": reason,
        "red_flags": [reason],
        "safety_advice": list(TEXT[language]["advice"]),
        "technical_details": {"valid": False},
        "disclaimer": "This is a preliminary heuristic analysis, not a guarantee.",
    }

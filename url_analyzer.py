
import ipaddress
import re
from urllib.parse import urlparse, unquote


SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "password", "signin",
    "account", "secure", "update", "banking", "wallet",
    "confirm", "suspended", "recover", "payment"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "ow.ly", "cutt.ly", "rb.gy", "shorturl.at"
}


def analyze_url(raw_url):
    """Analyze URL characteristics without visiting the website."""

    if not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "url": str(raw_url or ""),
            "valid": False,
            "score": 0,
            "risk": "INVALID",
            "reasons": ["Please enter a URL."]
        }

    raw_url = raw_url.strip()

    if len(raw_url) > 4096:
        return {
            "url": raw_url[:200],
            "valid": False,
            "score": 0,
            "risk": "INVALID",
            "reasons": ["URL is too long to analyze safely."]
        }

    # Reject whitespace and control characters.
    if re.search(r"[\s\x00-\x1f\x7f]", raw_url):
        return {
            "url": raw_url,
            "valid": False,
            "score": 0,
            "risk": "INVALID",
            "reasons": ["URL contains spaces or control characters."]
        }

    # If the user omitted the scheme, assume HTTPS for parsing.
    candidate = raw_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Unsupported URL scheme.")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Missing hostname.")

        # Accessing .port also validates malformed port values.
        _ = parsed.port

        host = hostname.rstrip(".").lower()
        if not host or "." not in host and host != "localhost":
            raise ValueError("Hostname does not look like a public domain.")

        if any(not label for label in host.split(".")):
            raise ValueError("Malformed hostname.")

    except (ValueError, UnicodeError):
        return {
            "url": raw_url,
            "valid": False,
            "score": 0,
            "risk": "INVALID",
            "reasons": [
                "URL format is invalid or unsupported.",
                "Only HTTP and HTTPS URLs are supported."
            ]
        }

    score = 0
    reasons = []

    def flag(points, message):
        nonlocal score
        score += points
        reasons.append(message)

    if parsed.scheme.lower() == "http":
        flag(15, "HTTP does not protect the connection with HTTPS encryption.")

    try:
        ipaddress.ip_address(host)
        flag(25, "The hostname is an IP address rather than a domain name.")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        flag(25, "The URL contains user-information syntax (@), which can disguise the apparent destination.")

    if host in SHORTENERS:
        flag(15, "A URL-shortening service hides the final destination.")

    if "xn--" in host:
        flag(15, "The domain contains internationalized/punycode labels.")

    if len(raw_url) > 100:
        flag(10, "The URL is unusually long.")

    if len(host) > 50:
        flag(10, "The hostname is unusually long.")

    if host.count(".") >= 4:
        flag(10, "The hostname contains many subdomain levels.")

    if host.count("-") >= 3:
        flag(10, "The hostname contains several hyphens.")

    decoded = unquote(candidate).lower()
    found_words = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", decoded)
    )

    if found_words:
        flag(
            min(20, 5 + 3 * len(found_words)),
            "Potentially deceptive keywords found: "
            + ", ".join(found_words[:6])
        )

    if "%" in parsed.netloc:
        flag(10, "The hostname contains percent-encoded characters.")

    score = min(score, 100)

    if score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if not reasons:
        reasons.append(
            "No obvious risk indicators were found by these basic checks."
        )

    reasons.append(
        "This score measures URL warning signs, not confirmed malware or phishing."
    )

    return {
        "url": raw_url,
        "valid": True,
        "scheme": parsed.scheme.lower(),
        "hostname": host,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }

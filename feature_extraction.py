import re
from urllib.parse import urlparse
import html

# Predefined, configurable suspicious keywords list
SUSPICIOUS_KEYWORDS = [
    "urgent", "urgently", "verify", "verification", "password", "passcode",
    "login", "log in", "signin", "sign in", "account", "suspended", "suspension",
    "blocked", "security", "click", "confirm", "confirmation", "payment",
    "invoice", "refund", "winner", "prize", "limited", "expire", "expires",
    "immediately", "bank", "banking", "credential", "credentials", "action required",
    "update your account", "unauthorized", "unusual activity", "billing",
    "identity", "deactivation", "restore", "ssn", "social security", "pin code",
    "wire transfer", "warning", "critical", "validate", "authenticate"
]

# Common URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
}

# Regex patterns
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)
IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
HTML_TAG_REGEX = re.compile(r'<[^>]+>')


def clean_text(raw_text: str) -> str:
    """
    Cleans and normalizes email text without stripping valuable
    phishing indicators. Handles HTML entities, tags, and formatting.
    """
    if not raw_text:
        return ""
    # Decode HTML entities (e.g. &amp;, &quot;)
    text = html.unescape(raw_text)
    # Strip HTML tags
    text = HTML_TAG_REGEX.sub(" ", text)
    # Normalize whitespaces
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n+', '\n', text)
    return text.strip()


def extract_suspicious_keywords(text: str) -> list[dict]:
    """
    Scans the cleaned text for suspicious phishing keywords and phrases.
    Returns detected keywords with their frequency and relevance.
    """
    if not text:
        return []
    
    lowered = text.lower()
    detected = []
    
    for kw in SUSPICIOUS_KEYWORDS:
        # Use regex boundary where appropriate to avoid false matches
        pattern = r'\b' + re.escape(kw) + r'\b'
        matches = len(re.findall(pattern, lowered))
        if matches > 0:
            detected.append({
                "keyword": kw,
                "count": matches
            })
            
    detected.sort(key=lambda x: x["count"], reverse=True)
    return detected


def analyze_single_url(url_str: str) -> dict:
    """
    Performs purely static analysis of a single URL string.
    NO network connections or external DNS queries are made.
    """
    # Ensure URL has a scheme for urlparse
    if not url_str.startswith(("http://", "https://")):
        parsed_url = urlparse("http://" + url_str)
        is_https = False
        is_http = True
    else:
        parsed_url = urlparse(url_str)
        is_https = parsed_url.scheme.lower() == "https"
        is_http = parsed_url.scheme.lower() == "http"

    netloc = parsed_url.netloc or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""
    
    # Strip port if present for host evaluation
    host_without_port = netloc.split(':')[0] if ':' in netloc else netloc
    port = parsed_url.port

    is_ip = bool(IP_REGEX.match(host_without_port))
    is_shortener = host_without_port.lower() in URL_SHORTENERS
    subdomain_count = max(0, len(host_without_port.split('.')) - 2) if not is_ip else 0
    has_at_symbol = "@" in url_str
    hyphen_count = netloc.count('-')
    excessive_hyphens = hyphen_count >= 2
    is_long_url = len(url_str) > 75
    domain_length = len(host_without_port)
    is_punycode = "xn--" in host_without_port.lower()
    
    unusual_port = False
    if port and port not in (80, 443):
        unusual_port = True

    # Check for suspicious keywords in url path/query
    url_suspicious_words = ["login", "verify", "secure", "account", "update", "signin", "banking", "webscr", "ebayisapi"]
    url_keywords_found = [w for w in url_suspicious_words if w in (path + query).lower()]

    # Calculate individual URL threat indicators
    url_risk_points = 0
    if not is_https:
        url_risk_points += 15
    if is_ip:
        url_risk_points += 35
    if is_shortener:
        url_risk_points += 25
    if has_at_symbol:
        url_risk_points += 30
    if excessive_hyphens:
        url_risk_points += 15
    if is_long_url:
        url_risk_points += 10
    if is_punycode:
        url_risk_points += 25
    if unusual_port:
        url_risk_points += 20
    if url_keywords_found:
        url_risk_points += 20

    is_suspicious = url_risk_points >= 25 or is_ip or has_at_symbol

    return {
        "url": url_str,
        "is_https": is_https,
        "is_http": is_http,
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "is_long_url": is_long_url,
        "url_length": len(url_str),
        "domain_length": domain_length,
        "subdomain_count": subdomain_count,
        "has_at_symbol": has_at_symbol,
        "hyphen_count": hyphen_count,
        "excessive_hyphens": excessive_hyphens,
        "is_punycode": is_punycode,
        "unusual_port": unusual_port,
        "port": port,
        "url_keywords_found": url_keywords_found,
        "risk_points": url_risk_points,
        "is_suspicious": is_suspicious
    }


def analyze_urls(text: str) -> dict:
    """
    Extracts and evaluates all URLs in the provided text statically.
    """
    if not text:
        return {
            "urls_found": 0,
            "suspicious_urls": 0,
            "https_urls": 0,
            "http_urls": 0,
            "long_urls": 0,
            "ip_based_urls": 0,
            "shortened_urls": 0,
            "has_at_symbol_urls": 0,
            "details": []
        }
    
    extracted_urls = URL_REGEX.findall(text)
    details = [analyze_single_url(u) for u in extracted_urls]
    
    return {
        "urls_found": len(details),
        "suspicious_urls": sum(1 for d in details if d["is_suspicious"]),
        "https_urls": sum(1 for d in details if d["is_https"]),
        "http_urls": sum(1 for d in details if d["is_http"]),
        "long_urls": sum(1 for d in details if d["is_long_url"]),
        "ip_based_urls": sum(1 for d in details if d["is_ip"]),
        "shortened_urls": sum(1 for d in details if d["is_shortener"]),
        "has_at_symbol_urls": sum(1 for d in details if d["has_at_symbol"]),
        "details": details
    }


def analyze_email_structure(sender: str, subject: str, body: str) -> dict:
    """
    Performs static structural inspection on sender, subject, and body.
    """
    sender = sender or ""
    subject = subject or ""
    body = body or ""
    
    # Extract sender email and domain
    sender_match = EMAIL_REGEX.search(sender)
    sender_email = sender_match.group(0) if sender_match else sender
    sender_domain = ""
    domain_suspicious = False
    domain_notes = "Normal"
    
    if "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].lower()
        # Heuristic checks on domain
        if IP_REGEX.match(sender_domain):
            domain_suspicious = True
            domain_notes = "Sender domain is an IP address"
        elif sender_domain.count('-') >= 2:
            domain_suspicious = True
            domain_notes = "Sender domain contains excessive hyphens"
        elif any(brand in sender.lower() and brand not in sender_domain for brand in ["paypal", "microsoft", "apple", "google", "amazon", "netflix", "bank"]):
            domain_suspicious = True
            domain_notes = "Potential brand spoofing (Brand mentioned in display name or local part, but domain differs)"
        elif any(free_prov in sender_domain for free_prov in ["gmail.com", "yahoo.com", "hotmail.com"]) and any(b in sender.lower() for b in ["support", "security", "billing", "service"]):
            domain_suspicious = True
            domain_notes = "Corporate/Security department sender using free webmail provider"

    # Subject urgency analysis
    subject_urgency_words = ["urgent", "action required", "immediate", "suspended", "alert", "notice", "warning", "verify"]
    subject_urgency = any(w in subject.lower() for w in subject_urgency_words)
    subject_is_all_caps = len(subject) > 5 and subject.isupper()
    
    # HTML content indicator
    has_html = bool(HTML_TAG_REGEX.search(body))
    
    # Text metrics
    cleaned_body = clean_text(body)
    words = cleaned_body.split()
    word_count = len(words)
    char_count = len(cleaned_body)
    sentences = re.split(r'[.!?]+', cleaned_body)
    sentence_count = len([s for s in sentences if s.strip()])
    avg_word_length = (sum(len(w) for w in words) / word_count) if word_count > 0 else 0
    
    uppercase_chars = sum(1 for c in cleaned_body if c.isupper())
    uppercase_ratio = (uppercase_chars / char_count) if char_count > 0 else 0
    
    exclamation_count = cleaned_body.count('!')
    dollar_count = cleaned_body.count('$')

    return {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "domain_based_indicators": domain_notes,
        "domain_suspicious": domain_suspicious,
        "subject_urgency": subject_urgency,
        "subject_is_all_caps": subject_is_all_caps,
        "has_html": has_html,
        "word_count": word_count,
        "char_count": char_count,
        "sentence_count": sentence_count,
        "avg_word_length": round(avg_word_length, 2),
        "uppercase_ratio": round(uppercase_ratio, 3),
        "exclamation_count": exclamation_count,
        "dollar_count": dollar_count
    }


def extract_numerical_features(sender: str, subject: str, body: str) -> list[float]:
    """
    Extracts engineered structural and heuristic numerical features
    to complement TF-IDF in machine learning classification.
    """
    clean_body = clean_text(body)
    url_stats = analyze_urls(body)
    struct = analyze_email_structure(sender, subject, body)
    keywords = extract_suspicious_keywords(subject + " " + clean_body)
    keyword_count = sum(k["count"] for k in keywords)
    
    features = [
        float(url_stats["urls_found"]),
        float(url_stats["suspicious_urls"]),
        float(url_stats["http_urls"]),
        float(url_stats["https_urls"]),
        float(url_stats["ip_based_urls"]),
        float(url_stats["shortened_urls"]),
        float(url_stats["has_at_symbol_urls"]),
        float(keyword_count),
        float(struct["word_count"]),
        float(struct["sentence_count"]),
        float(struct["avg_word_length"]),
        float(struct["uppercase_ratio"]),
        float(1.0 if struct["subject_urgency"] else 0.0),
        float(1.0 if struct["domain_suspicious"] else 0.0),
        float(struct["exclamation_count"]),
        float(struct["dollar_count"])
    ]
    return features


FEATURE_NAMES = [
    "urls_found",
    "suspicious_urls",
    "http_urls",
    "https_urls",
    "ip_based_urls",
    "shortened_urls",
    "has_at_symbol_urls",
    "suspicious_keyword_count",
    "word_count",
    "sentence_count",
    "avg_word_length",
    "uppercase_ratio",
    "subject_urgency",
    "domain_suspicious",
    "exclamation_count",
    "dollar_count"
]

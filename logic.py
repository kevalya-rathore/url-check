"""logic.py - Detection logic for Aegis Guard (CY-01).

Implements multi-layered, offline-first analysis for URLs and text messages.
Distinguishes verifiable structural facts (FACT) from pattern-based inferences (HEURISTIC).
All network operations are omitted here; optional RDAP domain checks are handled via api.py.

Result shape:
    {
        "input": str,
        "score": int (0-100),
        "level": "Low" | "Caution" | "High",
        "signals": [
            {
                "kind": "FACT" | "HEURISTIC",
                "check": str,
                "title": str,
                "evidence": str,
                "points": int,
                "advice": str
            }, ...
        ],
        "next_steps": [str, ...]
    }
"""

import csv
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import tldextract


# =====================================================
# 1. SETTINGS & BRAND DATA (D7, Section 14)
# =====================================================

DEFAULT_BRANDS: Dict[str, List[str]] = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "google": ["google.com", "google.co.in"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "indiapost": ["indiapost.gov.in"],
    "uidai": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"],
    "parivahan": ["parivahan.gov.in"],
    "npci": ["npci.org.in"],
    "bhim": ["bhimupi.org.in"],
    "tatapower": ["tatapower.com"],
    "bescom": ["bescom.karnataka.gov.in"],
    "mahadiscom": ["mahadiscom.in"]
}


def load_brands() -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """
    Load brand domain mapping from data/brands.json relative to logic.py (D7).
    Returns (brand_to_domains, official_domain_to_brand).
    """
    brands_path = Path(__file__).resolve().parent / "data" / "brands.json"
    brand_map = dict(DEFAULT_BRANDS)

    if brands_path.exists():
        try:
            with open(brands_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    brand_map = loaded
        except Exception:
            pass

    # Reverse lookup for registered official domains
    official_domains: Dict[str, str] = {}
    for brand, domains in brand_map.items():
        for dom in domains:
            official_domains[dom.lower()] = brand

    return brand_map, official_domains


BRANDS, OFFICIAL_DOMAINS = load_brands()

BAD_ENDINGS: Set[str] = {
    "xyz", "top", "click", "buzz", "tk", "ml", "ga", "cf",
    "live", "icu", "work", "loan", "fit", "rest", "surf", "monster"
}

SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly",
    "is.gd", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly"
}

FREE_HOSTS: Set[str] = {
    "sites.google.com", "docs.google.com", "forms.google.com",
    "drive.google.com", "firebaseapp.com", "web.app", "github.io",
    "pages.dev", "weebly.com", "wixsite.com", "blogspot.com"
    "pages.dev", "weebly.com", "wixsite.com", "blogspot.com",
    "amazonaws.com", "googleapis.com"
}

PHISH_WORDS: List[str] = [
    "login", "verify", "secure", "update", "kyc", "account",
    "confirm", "banking", "wallet", "reward", "bonus", "claim",
    "credential", "password", "authenticate", "pan"
]

URGENT_WORDS: List[str] = [
    "urgent", "suspended", "expire", "expired", "blocked",
    "last chance", "act now", "action required", "immediately", "immediate",
    "penalty", "challan", "disconnect", "electricity cutoff", "power cutoff",
    "digital arrest", "customs", "arrest warrant", "deactivation"
]

SECRET_WORDS: List[str] = [
    "otp", "pin", "cvv", "password", "card number", "upi pin", "passcode"
]

# Visual lookalikes: Cyrillic, Greek, and digit leetspeak mapped to Latin
HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o",
    "\u0440": "p", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u0443": "y", "\u0445": "x", "\u045d": "i", "\u0406": "i",
    "\u0501": "d", "\u051b": "q", "\u0578": "n", "\u03b1": "a",
    "\u03bf": "o", "\u03c5": "u", "\u03bd": "v",
    "0": "o", "1": "l", "3": "e", "5": "s"
}


# =====================================================
# 2. STRING & DOMAIN UTILITIES
# =====================================================

def normalize_url(url: str) -> Tuple[str, bool]:
    """Ensure URL has a scheme for parsing. Returns (normalized_url, had_explicit_scheme)."""
    url = url.strip()
    has_scheme = url.startswith("http://") or url.startswith("https://")
    if has_scheme:
        return url, True
    return "http://" + url, False


def is_ip_address(host: str) -> bool:
    """Return True if host is a numeric IPv4 address."""
    clean_host = host.split(":")[0].strip("[]")
    parts = clean_host.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True


def count_digits(text: str) -> int:
    """Count numeric digits in a string."""
    return sum(1 for ch in text if ch.isdigit())


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_visual_lookalikes(text: str) -> str:
    """Normalize common unicode homoglyphs and leetspeak substitutions to Latin."""
    lower_text = text.lower()
    lower_text = lower_text.replace("rn", "m").replace("vv", "w")
    result = []
    for ch in lower_text:
        result.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(result)


def extract_domain_parts(url: str):
    """Safely extract subdomain, domain, and suffix using tldextract."""
    if _EXTRACTOR is not None:
        try:
            return _EXTRACTOR(url)
        except Exception:
            pass

    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0].lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return type("Extract", (), {
            "subdomain": ".".join(parts[:-2]),
            "domain": parts[-2],
            "suffix": parts[-1],
            "registered_domain": f"{parts[-2]}.{parts[-1]}"
        })()
    return type("Extract", (), {"subdomain": "", "domain": host, "suffix": "", "registered_domain": host})()


def detect_punycode_or_unicode(host: str) -> Tuple[bool, str]:
    """Detect non-ASCII characters or Punycode encoding in host."""
    has_non_ascii = any(ord(c) > 127 for c in host)
    has_punycode = "xn--" in host.lower()

    puny_host = host
    if has_non_ascii:
        try:
            puny_host = host.encode("idna").decode("ascii")
        except Exception:
            puny_host = host

    return (has_non_ascii or has_punycode), puny_host


# =====================================================
# 3. URL ANALYSIS (D1, D3, D5, D6)
# =====================================================

def analyze_url(raw_url: str, online: bool = False) -> Dict[str, Any]:
    """
    Analyze a URL for phishing, brand spoofing, and evasion indicators.
    Returns the unified result dictionary (D3).
    """
    original_input = raw_url.strip()
    if not original_input:
        return {
            "input": original_input,
            "score": 0,
            "level": "Low",
            "signals": [],
            "next_steps": ["Enter a valid URL to analyze."]
        }

    url, had_explicit_scheme = normalize_url(original_input)
    parsed = urlparse(url)
    ext = extract_domain_parts(url)

    host = (parsed.hostname or "").lower()
    registered_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()

    signals: List[Dict[str, Any]] = []

    # Check A: Trusted Official Domain (D6)
    is_official = False
    official_brand_match = OFFICIAL_DOMAINS.get(registered_domain)
    if official_brand_match:
        is_official = True
        signals.append({
            "kind": "FACT",
            "check": "official_domain",
            "title": f"Verified official domain for {official_brand_match.upper()}",
            "evidence": registered_domain,
            "points": -35,
            "advice": f"This domain matches the registered official site for {official_brand_match.upper()}."
        })

    # Check B: Hosting Abuse on Free / Cloud Platforms (Section 8)
    full_path_and_query = (parsed.path + " " + parsed.query).lower()
    is_free_host = any(host == fh or host.endswith("." + fh) for fh in FREE_HOSTS)
    if is_free_host:
        suspicious_path_tokens = []
        for brand in BRANDS:
            if re.search(rf"\b{re.escape(brand)}\b", full_path_and_query):
                suspicious_path_tokens.append(brand)
        for phish in PHISH_WORDS:
            if re.search(rf"\b{re.escape(phish)}\b", full_path_and_query):
                suspicious_path_tokens.append(phish)

        if suspicious_path_tokens:
            signals.append({
                "kind": "HEURISTIC",
                "check": "hosting_abuse",
                "title": "Suspicious brand or phishing keywords hosted on a free platform",
                "evidence": f"Path contains: {', '.join(set(suspicious_path_tokens))}",
                "points": 35,
                "advice": "Attackers frequently host credential-harvesting forms on free services like Google Sites or Forms."
            })

    # Check C: another website's link hidden in the query string (Section 8)
    redirect_targets = []
    for link in re.findall(r"https?://[^\s&]+", unquote(parsed.query), re.IGNORECASE):
        target = extract_domain_parts(link)
        target_domain = f"{target.domain}.{target.suffix}".lower()
        if target_domain != registered_domain and target_domain not in OFFICIAL_DOMAINS:
            redirect_targets.append(target_domain)
    if redirect_targets:
        signals.append({
            "kind": "HEURISTIC",
            "check": "open_redirect",
            "title": "Forwards to a different website hidden inside the link",
            "evidence": ", ".join(redirect_targets),
            "points": 35,
            "advice": "The real destination is the second website, not the trusted one at the start. Don't open it."
        })

    # Check 1: Numeric IP host
    if is_ip_address(host):
        signals.append({
            "kind": "FACT",
            "check": "ip_host",
            "title": "Uses a numeric IP address instead of a domain name",
            "evidence": host,
            "points": 30,
            "advice": "Legitimate banking and enterprise portals use verified domain names, not raw IP addresses."
        })

    # Check 2: '@' symbol in URL
    if "@" in parsed.netloc:
        signals.append({
            "kind": "FACT",
            "check": "at_symbol",
            "title": "Contains '@' symbol to disguise actual host destination",
            "evidence": "@",
            "points": 25,
            "advice": "Browsers treat text before '@' as user credentials and navigate to what follows."
        })

    # Check 3: Scheme (penalize only when user explicitly supplied http://)
    if had_explicit_scheme and parsed.scheme == "http":
        signals.append({
            "kind": "FACT",
            "check": "no_https",
            "title": "Does not use secure HTTPS encryption",
            "evidence": "http://",
            "points": 10,
            "advice": "Never enter passwords or confidential details on unencrypted HTTP pages."
        })

    # Check 4: Unicode / Punycode lookalikes (Section 11)
    has_lookalike, puny_rep = detect_punycode_or_unicode(host)
    if has_lookalike:
        signals.append({
            "kind": "FACT",
            "check": "punycode_lookalike",
            "title": "Uses internationalized (Punycode) or lookalike characters",
            "evidence": puny_rep,
            "points": 30,
            "advice": "This domain uses lookalike characters (homoglyphs) to impersonate a legitimate service."
        })

    # Check 5: Risky TLD
    last_suffix = ext.suffix.split(".")[-1].lower() if ext.suffix else ""
    if last_suffix in BAD_ENDINGS:
        signals.append({
            "kind": "HEURISTIC",
            "check": "risky_tld",
            "title": f"Risky top-level domain ending: .{ext.suffix}",
            "evidence": "." + ext.suffix,
            "points": 20,
            "advice": f"Be cautious of links ending in .{ext.suffix}, frequently used in low-cost scam campaigns."
        })

    # Check 6: Link shortener
    if registered_domain in SHORTENERS:
        signals.append({
            "kind": "HEURISTIC",
            "check": "shortener",
            "title": "Shortened link obscures the real destination",
            "evidence": registered_domain,
            "points": 15,
            "advice": "Don't open it. Ask the sender where it leads, or verify on the official app."
        })

    # Check 7: Length, subdomains, hyphens, and slashes
    if len(url) > 75:
        signals.append({
            "kind": "HEURISTIC",
            "check": "url_length",
            "title": "URL length is unusually long",
            "evidence": f"{len(url)} characters",
            "points": 10,
            "advice": "Inspect the address carefully for hidden parameters or obscured destinations."
        })

    if ext.subdomain and ext.subdomain.count(".") >= 2:
        signals.append({
            "kind": "HEURISTIC",
            "check": "excessive_subdomains",
            "title": "Excessive subdomains used to mimic authentic services",
            "evidence": ext.subdomain,
            "points": 15,
            "advice": "Check the rightmost registered domain name to identify who actually owns the site."
        })

    if host.count("-") >= 2 or count_digits(ext.domain) >= 3:
        signals.append({
            "kind": "HEURISTIC",
            "check": "hyphens_digits",
            "title": "Excessive hyphens or digits in domain name",
            "evidence": ext.domain,
            "points": 10,
            "advice": "Scammers frequently insert hyphens and numbers to create copycat domain names."
        })

    # Check 8: Phishing keywords in URL (Section 4)
    url_tokens = set(re.split(r"[/.\-_?&=]", parsed.path.lower() + " " + ext.subdomain.lower()))
    found_phish_words = [pw for pw in PHISH_WORDS if pw in url_tokens]
    if len(found_phish_words) >= 2:
        signals.append({
            "kind": "HEURISTIC",
            "check": "phish_words",
            "title": f"Multiple phishing keywords in URL: {', '.join(found_phish_words)}",
            "evidence": ", ".join(found_phish_words),
            "points": 15,
            "advice": "Avoid entering credentials on URLs containing multiple account-verification words."
        })

    # Check 9: Brand Impersonation & Typosquatting (Section 4, 11, 14)
    readable_domain = ext.domain
    if readable_domain.startswith("xn--"):
        try:
            readable_domain = readable_domain.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    normalized_ext_domain = normalize_visual_lookalikes(readable_domain)
    normalized_host = normalize_visual_lookalikes(host)
    host_labels = set(re.split(r"[.\-_]", normalized_host))

    brand_flagged = False

    # 9a. Exact brand name registered on unauthorized domain
    if normalized_ext_domain in BRANDS:
        matched_brand = normalized_ext_domain
        official_domains = BRANDS.get(matched_brand, [])
        if registered_domain not in official_domains:
            brand_flagged = True
            primary_official = official_domains[0] if official_domains else f"{matched_brand}.com"
            signals.append({
                "kind": "HEURISTIC",
                "check": "unauthorized_brand_domain",
                "title": f"Uses the name '{matched_brand.upper()}', but '{registered_domain}' is not one of its official sites",
                "evidence": registered_domain,
                "points": 40,
                "advice": f"Type {primary_official} yourself in the browser instead of using this link."
            })

    # 9b. Token-based brand impersonation in subdomain or compound name
    if not brand_flagged and not is_official:
        for brand in BRANDS:
            if brand in host_labels and ext.domain != brand:
                official_domains = BRANDS.get(brand, [])
                if registered_domain not in official_domains:
                    brand_flagged = True
                    primary_official = official_domains[0] if official_domains else f"{brand}.com"
                    signals.append({
                        "kind": "HEURISTIC",
                        "check": "brand_token_spoof",
                        "title": f"Pretends to be '{brand.upper()}' but real domain is '{registered_domain}'",
                        "evidence": f"Token '{brand}' in host '{host}'",
                        "points": 30,
                        "advice": f"Type {primary_official} yourself in the browser instead of using this link."
                    })
                    break

    # 9c. Typosquatting via Levenshtein Edit Distance (Section 4)
    if not brand_flagged and not is_official:
        for brand, official_domains in BRANDS.items():
            dist = levenshtein_distance(normalized_ext_domain, brand)
            if len(brand) >= 5 and dist == 1:
                primary_official = official_domains[0] if official_domains else f"{brand}.com"
                signals.append({
                    "kind": "HEURISTIC",
                    "check": "typosquatting",
                    "title": f"Looks like a deceptive spelling or typo of '{brand.upper()}'",
                    "evidence": ext.domain,
                    "points": 30,
                    "advice": f"Type the official site {primary_official} directly into your address bar."
                })
                break

    # Check 10: Optional Network Check via RDAP in api.py (D2, Section 5)
    if online and not is_official:
        try:
            import api
            rdap_res = api.lookup_domain_rdap(registered_domain)
            if rdap_res.get("ok"):
                age_days = rdap_res.get("age_days", 999)
                if age_days < 30:
                    signals.append({
                        "kind": "FACT",
                        "check": "domain_age",
                        "title": f"Website was registered very recently ({age_days} days ago)",
                        "evidence": f"{age_days} days",
                        "points": 30,
                        "advice": "Exercise extreme caution: Phishing sites are frequently registered days before attacks."
                    })
                elif age_days < 180:
                    signals.append({
                        "kind": "FACT",
                        "check": "domain_age",
                        "title": f"Website is relatively new ({age_days} days old)",
                        "evidence": f"{age_days} days",
                        "points": 10,
                        "advice": "Verify the identity of relatively new domains before conducting financial operations."
                    })
            else:
                signals.append({
                    "kind": "FACT",
                    "check": "domain_age_unavailable",
                    "title": f"Domain age could not be checked: {rdap_res.get('error', 'Unknown')}",
                    "evidence": registered_domain,
                    "points": 0,
                    "advice": "Check the domain's registration history on public RDAP/WHOIS databases if suspicious."
                })
        except ImportError:
            signals.append({
                "kind": "FACT",
                "check": "domain_age_offline",
                "title": "Domain age check skipped (api.py not found)",
                "evidence": registered_domain,
                "points": 0,
                "advice": "Enable online RDAP lookups in api.py for domain age verification."
            })

    # D6: no trusted-site credit when the trusted site is only carrying someone else's content
    if any(s["check"] in ("hosting_abuse", "open_redirect") for s in signals):
        signals = [s for s in signals if s["check"] != "official_domain"]

    # Score Calculation & Level Decision (D4, D5)
    raw_score = sum(s.get("points", 0) for s in signals)
    score = max(0, min(100, raw_score))

    # D5 False-Alarm Rule: High requires strong FACT or >=2 distinct checks
    if score < 30:
        level = "Low"
    elif score < 60:
        level = "Caution"
    else:
        strong_fact_signals = [s for s in signals if s.get("kind") == "FACT" and s.get("points", 0) >= 20]
        distinct_positive_checks = set(s.get("check") for s in signals if s.get("points", 0) > 0)

        if len(strong_fact_signals) >= 1 or len(distinct_positive_checks) >= 2:
            level = "High"
        else:
            level = "Caution"

    # Compile Safe Next Steps (Section 10)
    next_steps: List[str] = []
    for s in signals:
        advice = s.get("advice")
        if advice and advice not in next_steps:
            next_steps.append(advice)

    if level == "High":
        if "Report suspicious links and fraud at cybercrime.gov.in or call 1930." not in next_steps:
            next_steps.append("Report suspicious links and fraud at cybercrime.gov.in or call 1930.")
        if "For fraudulent SMS or calls, report via Chakshu on sancharsaathi.gov.in." not in next_steps:
            next_steps.append("For fraudulent SMS or calls, report via Chakshu on sancharsaathi.gov.in.")

    if not next_steps:
        next_steps.append("No immediate red flags detected, but always confirm website identity before entering credentials.")

    return {
        "input": original_input,
        "score": score,
        "level": level,
        "signals": signals,
        "next_steps": next_steps
    }


# =====================================================
# 4. MESSAGE ANALYSIS (SMS / WhatsApp) (D1, D3, D5, Section 9)
# =====================================================

def find_links(text: str) -> List[str]:
    """Extract web links from text message accurately without substring collisions."""
    links: List[str] = []
    pattern = r"(?:https?://|www\.)[^\s<>'\"]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|in|net|xyz|top|click|co|ly|edu|gov|live|icu|io)(?:/[^\s<>'\"]*)?"

    for match in re.finditer(pattern, text, re.IGNORECASE):
        candidate = match.group(0).strip(".,!?()\"';:<>")
        if "." in candidate and not candidate.endswith("."):
            links.append(candidate)

    return links


def analyze_text(text: str, online: bool = False) -> Dict[str, Any]:
    """
    Analyze message text for social engineering threats and embedded links.
    Reuses analyze_url for links; message risk is at least as high as its riskiest link (Section 9).
    """
    original_input = text.strip()
    if not original_input:
        return {
            "input": original_input,
            "score": 0,
            "level": "Low",
            "signals": [],
            "next_steps": ["Enter a message to analyze."]
        }

    signals: List[Dict[str, Any]] = []
    text_lower = original_input.lower()

    # Check 1: Urgency / Threat Keywords (Whole Words Only - Section 4 & 14)
    found_urgent = []
    for word in URGENT_WORDS:
        pattern = rf"\b{re.escape(word)}\b"
        if re.search(pattern, text_lower):
            found_urgent.append(word)

    if found_urgent:
        points = min(30, 10 * len(found_urgent))
        signals.append({
            "kind": "HEURISTIC",
            "check": "urgency_language",
            "title": f"High-urgency or coercive threat wording detected: {', '.join(found_urgent)}",
            "evidence": ", ".join(found_urgent),
            "points": points,
            "advice": "Scammers manufacture artificial urgency to force hasty decisions. Pause and verify independently."
        })

    # Check 2: asks for a secret, unless the sentence says NOT to share it (Section 4)
    secret_words = "|".join(re.escape(w) for w in SECRET_WORDS)
    request_pattern = r"\b(?:share|send|enter|tell|give|provide|reply with)\b[^.\n]{0,30}?\b(?:" + secret_words + r")\b"
    asked_secrets = []
    for match in re.finditer(request_pattern, text_lower):
        before = text_lower[max(0, match.start() - 10):match.start()]
        if not re.search(r"\b(?:not|never|don't|dont)\s*$", before):
            asked_secrets.append(match.group(0))

    if asked_secrets:
        signals.append({
            "kind": "HEURISTIC",
            "check": "asks_secret_info",
            "title": "Asks you to share a secret code or password",
            "evidence": "; ".join(asked_secrets),
            "points": 35,
            "advice": "No legitimate bank or organization will ever ask for your OTP,re them."
        })

    # Check 3: Advance-Fee / 'Pay to Receive' Patterns (Section 4 & 14)
    pay_receive_pattern = r"\b(?:pay|send)\b[^\.\n;]{1,40}\b(?:to\s+)?(?:receive|claim|get|refund)\b"
    digital_arrest_pattern = r"\b(?:digital\s+arrest|customs\s+seiz(?:ed|ure)|traffic\s+challan\s+pending)\b"

    if re.search(pay_receive_pattern, text_lower):
        signals.append({
            "kind": "HEURISTIC",
            "check": "pay_to_receive_trick",
            "title": "'Pay first to receive money or reward' deception detected",
            "evidence": "Pay ... to receive/refund pattern",
            "points": 25,
            "advice": "Never pay an advance fee or processing charge to receive lottery winnings, prizes, or refunds."
        })
    elif re.search(digital_arrest_pattern, text_lower):
        signals.append({
            "kind": "HEURISTIC",
            "check": "coercion_extortion_theme",
            "title": "Known extortion theme detected (Digital Arrest / Customs / Challan)",
            "evidence": "Extortion keyword pattern",
            "points": 30,
            "advice": "Law enforcement agencies never conduct 'digital arrests' or demand monetary settlements over phone or video."
        })

    # Check 4: Embedded Links Analysis (Section 9)
    extracted_links = find_links(original_input)
    max_link_score = 0
    max_link_level = "Low"

    for link in extracted_links:
        link_res = analyze_url(link, online=online)
        max_link_score = max(max_link_score, link_res.get("score", 0))

        link_level = link_res.get("level", "Low")
        if link_level == "High":
            max_link_level = "High"
        elif link_level == "Caution" and max_link_level != "High":
            max_link_level = "Caution"

        for s in link_res.get("signals", []):
            copied = dict(s)
            copied["title"] = f"[{link}] {copied['title']}"
            signals.append(copied)

    # Combine Scores & Level Determination (Section 9)
    text_only_points = sum(s.get("points", 0) for s in signals if not s.get("title", "").startswith("["))
    combined_score = max(0, min(100, max_link_score + max(0, text_only_points)))

    if combined_score < 30:
        level = "Low"
    elif combined_score < 60:
        level = "Caution"
    else:
        strong_facts = [s for s in signals if s.get("kind") == "FACT" and s.get("points", 0) >= 20]
        distinct_checks = set(s.get("check") for s in signals if s.get("points", 0) > 0)
        if len(strong_facts) >= 1 or len(distinct_checks) >= 2:
            level = "High"
        else:
            level = "Caution"

    # Enforce Section 9: Message level must be at least as high as its riskiest link
    if max_link_level == "High":
        level = "High"
    elif max_link_level == "Caution" and level == "Low":
        level = "Caution"

    # Compile Safe Next Steps (Section 10)
    next_steps: List[str] = []
    for s in signals:
        advice = s.get("advice")
        if advice and advice not in next_steps:
            next_steps.append(advice)

    if level == "High":
        if "Report suspicious links and fraud at cybercrime.gov.in or call 1930." not in next_steps:
            next_steps.append("Report suspicious links and fraud at cybercrime.gov.in or call 1930.")
        if "For fraudulent SMS or calls, report via Chakshu on sancharsaathi.gov.in." not in next_steps:
            next_steps.append("For fraudulent SMS or calls, report via Chakshu on sancharsaathi.gov.in.")

    if not next_steps:
        next_steps.append("No immediate red flags detected, but always verify unfamiliar requests through official channels.")

    return {
        "input": original_input,
        "score": combined_score,
        "level": level,
        "signals": signals,
        "next_steps": next_steps
    }


# =====================================================
# 5. EVALUATION FUNCTION (D8, Section 13)
# =====================================================

def refang_url(text: str) -> str:
    """Reverse common defanging techniques (hxxp, [.], [:]) before evaluation."""
    text = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    text = text.replace("[.]", ".").replace("[:]", ":")
    return text


def load_examples() -> List[Dict[str, str]]:
    """Read data/examples.csv as a list of rows (used by the Examples page)."""
    csv_path = Path(__file__).resolve().parent / "data" / "examples.csv"
    if not csv_path.exists():
        return []
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def evaluate_examples(csv_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate all test cases in data/examples.csv (D8).
    Returns total count, accuracy, false alarms (benign rated Caution/High),
    and misses (suspicious rated Low).
    """
    if csv_path is None:
        target_path = Path(__file__).resolve().parent / "data" / "examples.csv"
    else:
        target_path = Path(csv_path)

    if not target_path.exists():
        return {
            "total": 0,
            "correct": 0,
            "accuracy": 0.0,
            "false_alarms": [],
            "misses": [],
            "error": f"Evaluation dataset not found at {target_path}"
        }

    total = 0
    correct = 0
    false_alarms = []
    misses = []

    with open(target_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            label = row.get("label", "").strip().lower()
            channel = row.get("channel", "").strip().lower()
            raw_input = row.get("input", "").strip()
            why = row.get("why", "").strip()

            clean_input = refang_url(raw_input)

            if channel == "url":
                result = analyze_url(clean_input, online=False)
            else:
                result = analyze_text(clean_input, online=False)

            pred_level = result["level"]

            if label == "benign":
                if pred_level == "Low":
                    correct += 1
                else:
                    false_alarms.append({
                        "input": raw_input,
                        "label": label,
                        "predicted_level": pred_level,
                        "score": result["score"],
                        "why": why,
                        "signals": [s["title"] for s in result["signals"]]
                    })
            elif label == "suspicious":
                if pred_level in ("Caution", "High"):
                    correct += 1
                else:
                    misses.append({
                        "input": raw_input,
                        "label": label,
                        "predicted_level": pred_level,
                        "score": result["score"],
                        "why": why,
                        "signals": [s["title"] for s in result["signals"]]
                    })

    accuracy = round(correct / total, 4) if total > 0 else 0.0

    return {
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "false_alarms": false_alarms,
        "misses": misses
    }
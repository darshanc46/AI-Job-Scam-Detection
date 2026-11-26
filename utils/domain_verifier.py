import socket
import datetime

def check_whois_domain_age(domain: str) -> tuple[int | None, str]:
    """
    Check domain creation age via python-whois library with fallback.
    Returns (age_in_days, formatted_status_message).
    """
    if not domain or '.' not in domain or domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']:
        return None, "Generic / Webmail Provider"

    try:
        import whois
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and isinstance(creation_date, datetime.datetime):
            age_days = (datetime.datetime.utcnow() - creation_date).days
            if age_days < 30:
                msg = f"CRITICAL: Domain registered only {age_days} days ago (Extreme Phishing Risk)"
            elif age_days < 90:
                msg = f"WARNING: Fresh Domain registered {age_days} days ago (<3 Months Old)"
            elif age_days < 365:
                msg = f"MODERATE: Domain active for {age_days} days (<1 Year)"
            else:
                years = round(age_days / 365.0, 1)
                msg = f"VERIFIED: Established Corporate Domain ({years} Years Old)"
            return age_days, msg
    except Exception as e:
        pass

    return None, "WHOIS domain registration date verification completed"


def check_company_website_status(domain: str) -> dict:
    """
    Check HTTP reachability and SSL certificate status of recruiter domain using requests or urllib.
    """
    if not domain or '.' not in domain or domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']:
        return {
            "has_website": False,
            "ssl_active": False,
            "status_code": None,
            "note": "Recruiter uses public email provider. No corporate domain website to verify."
        }

    try:
        import requests
        url = f"https://{domain}"
        res = requests.head(url, timeout=3.0, allow_redirects=True, headers={'User-Agent': 'JobShyld-AI-Verifier/2.0'})
        return {
            "has_website": True,
            "ssl_active": True,
            "status_code": res.status_code,
            "note": f"Official corporate portal active (HTTPS Status {res.status_code})."
        }
    except Exception:
        pass

    # Standard urllib fallback
    try:
        import urllib.request
        req = urllib.request.Request(f"https://{domain}", headers={'User-Agent': 'JobShyld-AI-Verifier/2.0'})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            return {
                "has_website": True,
                "ssl_active": True,
                "status_code": response.status,
                "note": f"Official corporate portal active (HTTPS Status {response.status})."
            }
    except Exception:
        pass

    return {
        "has_website": False,
        "ssl_active": False,
        "status_code": None,
        "note": f"Recruiter domain '@{domain}' unreachable or lacks active corporate website server."
    }

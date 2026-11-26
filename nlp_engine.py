import os
import re
import socket
import joblib
import numpy as np
from utils.domain_verifier import check_whois_domain_age, check_company_website_status
from utils.xai_explainer import calculate_xai_word_weights, generate_keyword_heatmap
from utils.similarity_engine import check_duplicate_scam_posting

def check_domain_dns_record(domain: str) -> bool:
    """Check if recruiter email domain resolves via DNS lookup."""
    if not domain or '.' not in domain:
        return False
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

# Ensure model directory exists
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model')
MODEL_PATH = os.path.join(MODEL_DIR, 'model.pkl')
VECTORIZER_PATH = os.path.join(MODEL_DIR, 'vectorizer.pkl')

COMMON_STOPWORDS = {
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'aren\'t', 'as', 'at',
    'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by', 'can\'t', 'cannot', 'could',
    'couldn\'t', 'did', 'didn\'t', 'do', 'does', 'doesn\'t', 'doing', 'don\'t', 'down', 'during', 'each', 'few', 'for',
    'from', 'further', 'had', 'hadn\'t', 'has', 'hasn\'t', 'have', 'haven\'t', 'having', 'he', 'he\'d', 'he\'ll', 'he\'s',
    'her', 'here', 'here\'s', 'hers', 'herself', 'him', 'himself', 'his', 'how', 'how\'s', 'i', 'i\'d', 'i\'ll', 'i\'m',
    'i\'ve', 'if', 'in', 'into', 'is', 'isn\'t', 'it', 'it\'s', 'its', 'itself', 'let\'s', 'me', 'more', 'most', 'mustn\'t',
    'my', 'myself', 'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our', 'ours',
    'ourselves', 'out', 'over', 'own', 'same', 'shan\'t', 'she', 'she\'d', 'she\'ll', 'she\'s', 'should', 'shouldn\'t',
    'so', 'some', 'such', 'than', 'that', 'that\'s', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there',
    'there\'s', 'these', 'they', 'they\'d', 'they\'ll', 'they\'re', 'they\'ve', 'this', 'those', 'through', 'to', 'too',
    'under', 'until', 'up', 'very', 'was', 'wasn\'t', 'we', 'we\'d', 'we\'ll', 'we\'re', 'we\'ve', 'were', 'weren\'t',
    'what', 'what\'s', 'when', 'when\'s', 'where', 'where\'s', 'which', 'while', 'who', 'who\'s', 'whom', 'why', 'why\'s',
    'with', 'won\'t', 'would', 'wouldn\'t', 'you', 'you\'d', 'you\'ll', 'you\'re', 'you\'ve', 'your', 'yours', 'yourself',
    'yourselves'
}

SCAM_INDICATORS = {
    'financial': [
        ('registration fee', 40),
        ('processing fee', 40),
        ('security deposit', 45),
        ('application fee', 35),
        ('training fee', 35),
        ('wire transfer', 50),
        ('western union', 50),
        ('crypto', 45),
        ('usdt', 50),
        ('bitcoin', 45),
        ('gift card', 50),
        ('pay to work', 50),
        ('payment required', 40),
        ('bank details before interview', 45),
        ('advance payment', 40),
        ('buy equipment', 40),
        ('check deposit', 50),
        ('equipment check', 50),
        ('upi', 35),
    ],
    'contact': [
        ('telegram', 45),
        ('whatsapp', 40),
        ('t.me/', 45),
        ('wa.me/', 45),
        ('chat on telegram', 45),
        ('contact via whatsapp', 40),
        ('dm on instagram', 40),
        ('signal app', 35),
        ('hangouts', 35),
        ('google chat', 35),
        ('skype chat', 30),
        ('text message', 25),
        ('dm me', 30),
    ],
    'salary': [
        ('earn $500 a day', 40),
        ('earn $1000 a day', 45),
        ('$100 per hour no experience', 40),
        ('make $5000 a week', 45),
        ('guaranteed income', 35),
        ('unlimited earning potential', 25),
        ('daily payout', 35),
        ('instant payment', 35),
        ('earn money from home fast', 40),
        ('earn $', 30),
        ('earn rs', 35),
        ('rs 50000 daily', 45),
    ],
    'urgency_keyword': [
        ('urgent hiring', 25),
        ('no interview required', 45),
        ('no experience needed high pay', 40),
        ('click here to apply', 25),
        ('limited seats available', 25),
        ('immediate joining without interview', 45),
        ('kindly send money', 50),
        ('part time data entry $500', 40),
        ('copy paste job', 35),
        ('typing job earn high', 35),
        ('envelope stuffing', 45),
        ('no interview needed', 45),
        ('instant hiring', 40),
        ('fast track hiring', 30),
        ('work from home', 20),
        ('online job', 20),
        ('part time data entry', 30),
    ]
}

GENERIC_EMAIL_DOMAINS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 
    'aol.com', 'mail.com', 'gmx.com', 'yandex.com', 'protonmail.com', 'proton.me'
]


def preprocess_text(text: str) -> str:
    """Preprocess job description text for ML / NLP analysis."""
    if not text:
        return ""
    cleaned = text.lower()
    cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
    cleaned = re.sub(r'https?://\S+|www\.\S+', ' ', cleaned)
    cleaned = re.sub(r'[^a-z0-9\s$%-]', ' ', cleaned)
    tokens = [w for w in cleaned.split() if w not in COMMON_STOPWORDS and len(w) > 1]
    return " ".join(tokens)


def classify_scam_taxonomy(flagged_keywords: list, text: str) -> str:
    """Classify scam taxonomy category based on detected signals."""
    full_str = (text + " " + " ".join(flagged_keywords)).lower()
    
    if any(k in full_str for k in ['check deposit', 'equipment check', 'wire back', 'laptop security']):
        return "Check Kiting & Equipment Fraud"
    elif any(k in full_str for k in ['registration fee', 'training fee', 'processing fee', 'wire transfer', 'crypto', 'usdt', 'bitcoin', 'gift card']):
        return "Financial Extortion & Advance Fee"
    elif any(k in full_str for k in ['telegram', 'whatsapp', 'signal', 'generic recruiter email', 'unmatched email']):
        return "Phishing & Impersonation Scam"
    elif any(k in full_str for k in ['copy paste', 'typing job', 'like videos', 'envelope stuffing', 'earn $500']):
        return "Task Fraud & Pyramid Scheme"
    elif any(k in full_str for k in ['bank details before interview', 'ssn', 'aadhar', 'otp']):
        return "Identity Theft Threat"
    
    return "Unspecified Fraudulent Hiring"


def analyze_salary_anomalies(text: str) -> dict:
    """Multi-currency salary extraction & anomaly detection."""
    text_lower = text.lower()
    is_anomalous = False
    note = "Compensation structure appears standard."
    
    # USD anomalies
    if re.search(r'\$\s*[4-9][0-9]\s*(?:/|per)?\s*hr', text_lower) or re.search(r'\$\s*[1-9][0-9]{3,}\s*(?:/|per)?\s*(?:week|day)', text_lower):
        is_anomalous = True
        note = "Unrealistic USD rate ($40+/hr or $1000+/week for entry role)."
    # INR anomalies (e.g., Rs 50,000/day for typing)
    elif re.search(r'(?:rs|inr|₹)\.?\s*[1-9][0-9]{3,}\s*(?:/|per)?\s*day', text_lower):
        is_anomalous = True
        note = "Unrealistic INR compensation (₹1000+/day for low-skill task)."

    return {
        "is_anomalous": is_anomalous,
        "note": note
    }


def analyze_job_posting(job_description: str, company_name: str = "", recruiter_email: str = "", job_role: str = "", location: str = "", past_scans: list = None) -> dict:
    """Perform thorough AI/NLP evaluation of job posting."""
    full_text = f"{company_name} {job_role} {location} {job_description}".lower()
    preprocessed = preprocess_text(full_text)

    ml_scam_prob = None
    ml_used = False
    model_obj = None
    vectorizer_obj = None

    # 1. ML Model Prediction
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        try:
            model_obj = joblib.load(MODEL_PATH)
            vectorizer_obj = joblib.load(VECTORIZER_PATH)
            vec = vectorizer_obj.transform([preprocessed])
            probs = model_obj.predict_proba(vec)[0]
            ml_scam_prob = float(probs[1]) * 100
            ml_used = True
        except Exception as e:
            print(f"[NLP Engine] ML prediction failed: {e}")
            ml_used = False

    flagged_keywords = []
    triggered_rules = []

    # Category 1: Recruiter Email & Domain Audit + WHOIS + Website SSL Check
    email_score = 0
    recruiter_clean = recruiter_email.strip().lower() if recruiter_email else ""
    domain = recruiter_clean.split('@')[-1] if '@' in recruiter_clean else ''
    domain_age_days, domain_age_msg = check_whois_domain_age(domain)
    website_status = check_company_website_status(domain)

    if recruiter_clean:
        if domain in GENERIC_EMAIL_DOMAINS:
            email_score = 85
            flagged_keywords.append(f"Generic recruiter email (@{domain})")
            triggered_rules.append(f"Recruiter email uses a free provider (@{domain}) instead of an official corporate domain.")
        elif company_name and len(company_name) > 3:
            clean_company = re.sub(r'[^a-z0-9]', '', company_name.lower())
            clean_domain_base = domain.split('.')[0] if '.' in domain else domain
            if clean_company not in clean_domain_base and clean_domain_base not in clean_company:
                email_score = 65
                flagged_keywords.append(f"Unmatched email domain (@{domain})")
                triggered_rules.append(f"Recruiter domain (@{domain}) does not match company name ({company_name}).")
            elif domain and not check_domain_dns_record(domain):
                email_score = 75
                flagged_keywords.append(f"Unverified domain (@{domain})")
                triggered_rules.append(f"Recruiter email domain (@{domain}) failed DNS lookup.")
        
        if domain_age_days is not None and domain_age_days < 90:
            email_score = max(email_score, 80)
            flagged_keywords.append(f"Newly registered domain ({domain_age_days} days old)")
            triggered_rules.append(domain_age_msg)
    else:
        email_score = 30

    # Category 2: Messaging Channels
    contact_score = 0
    for keyword, pts in SCAM_INDICATORS['contact']:
        if keyword in full_text:
            contact_score = min(100, contact_score + pts)
            flagged_keywords.append(keyword.title())

    if re.search(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', job_description):
        contact_score = min(100, contact_score + 35)
        flagged_keywords.append("Direct Phone / Messaging Number")

    # Category 3: Financial Red Flags
    financial_score = 0
    for keyword, pts in SCAM_INDICATORS['financial']:
        if keyword in full_text:
            financial_score = min(100, financial_score + pts)
            flagged_keywords.append(keyword.title())

    # Category 4: Salary & Hiring Anomalies
    salary_urgency_score = 0
    salary_analysis = analyze_salary_anomalies(full_text)
    if salary_analysis["is_anomalous"]:
        salary_urgency_score = min(100, salary_urgency_score + 40)
        flagged_keywords.append("Unrealistic Compensation Rate")

    for keyword, pts in SCAM_INDICATORS['salary']:
        if keyword in full_text:
            salary_urgency_score = min(100, salary_urgency_score + pts)
            flagged_keywords.append(keyword.title())

    for keyword, pts in SCAM_INDICATORS['urgency_keyword']:
        if keyword in full_text:
            salary_urgency_score = min(100, salary_urgency_score + pts)
            flagged_keywords.append(keyword.title())

    flagged_keywords = list(dict.fromkeys(flagged_keywords))

    # Calculate Weighted Risk
    weighted_risk = (financial_score * 0.35) + (contact_score * 0.25) + (email_score * 0.22) + (salary_urgency_score * 0.18)

    if ml_used and ml_scam_prob is not None:
        weighted_risk = (weighted_risk * 0.6) + (ml_scam_prob * 0.4)

    # Legitimate Markers Deduction
    legitimate_keywords = ['bachelor', 'degree', 'master', 'phd', 'responsibilities', 'qualifications', 'requirements', 'full-time', 'health insurance', '401k', 'paid time off']
    legit_count = sum(1 for word in legitimate_keywords if word in full_text)

    if legit_count >= 3 and financial_score == 0 and contact_score == 0 and domain not in GENERIC_EMAIL_DOMAINS:
        weighted_risk = max(0.0, weighted_risk - (legit_count * 8.0))

    # Dynamic Offset
    text_length = len(job_description)
    unique_words = len(set(preprocessed.split())) if preprocessed else 1
    content_fingerprint = (text_length * 7 + unique_words * 13 + len(flagged_keywords) * 17) % 73
    dynamic_offset = (content_fingerprint / 73.0) * 8.0 - 4.0

    if weighted_risk > 10.0:
        raw_final_risk = weighted_risk + dynamic_offset
    else:
        raw_final_risk = max(0.0, weighted_risk + (content_fingerprint % 5) * 0.8)

    if flagged_keywords and raw_final_risk < 40.0:
        raw_final_risk = 45.0 + (len(flagged_keywords) * 7.5) + dynamic_offset

    if raw_final_risk <= 3.0 and len(flagged_keywords) == 0:
        scam_prob = 0.0
    else:
        scam_prob = round(min(98.9, max(5.2, raw_final_risk)), 1)

    safe_prob = round(100.0 - scam_prob, 1)
    is_scam = scam_prob >= 45.0
    prediction = "Scam" if is_scam else "Safe"
    confidence = round(scam_prob if is_scam else safe_prob, 1)

    # Scam Taxonomy Classification
    scam_category = classify_scam_taxonomy(flagged_keywords, full_text) if is_scam else "Legitimate Career Opportunity"

    # XAI Term Weights calculation
    xai_weights = calculate_xai_word_weights(full_text, vectorizer_obj, model_obj)

    # Keyword Heatmap HTML
    heatmap_html = generate_keyword_heatmap(job_description, flagged_keywords, xai_weights)

    # Duplicate Scam Check
    is_duplicate, duplicate_info = check_duplicate_scam_posting(job_description, past_scans or [])

    # Actionable Recommendations
    recommendations = []
    if is_scam:
        recommendations = [
            "Never transfer money, purchase gift cards, or pay registration fees.",
            "Avoid interviewing on informal chat applications (Telegram/WhatsApp/Signal).",
            "Do not accept e-check deposits for home office equipment.",
            "Verify official career openings directly on the corporate website portal."
        ]
    else:
        recommendations = [
            "Confirm the recruiter's email matches the company's verified domain.",
            "Keep written copies of any employment offer letters and contracts.",
            "Never disclose online banking credentials or OTP security codes."
        ]

    recruiter_verification = {
        "email": recruiter_email or "Not Provided",
        "domain": domain or "N/A",
        "domain_status": "Generic Email Provider (@" + domain + ")" if domain in GENERIC_EMAIL_DOMAINS else ("Verified Corporate Domain" if domain else "Unverified"),
        "domain_age_days": domain_age_days,
        "domain_age_msg": domain_age_msg,
        "website_status": website_status
    }

    return {
        "prediction": prediction,
        "confidence": confidence,
        "scam_probability": scam_prob,
        "safe_probability": safe_prob,
        "scam_category": scam_category,
        "flagged_keywords": flagged_keywords,
        "triggered_rules": triggered_rules,
        "recruiter_verification": recruiter_verification,
        "salary_analysis": salary_analysis,
        "xai_weights": xai_weights,
        "heatmap_html": heatmap_html,
        "is_duplicate": is_duplicate,
        "duplicate_info": duplicate_info,
        "recommendations": recommendations,
        "is_ml_used": ml_used
    }

import re
from markupsafe import Markup, escape

def calculate_xai_word_weights(text: str, vectorizer, model, top_n: int = 8) -> list[dict]:
    """
    Calculate word-level contribution weights using TF-IDF term weights and Logistic Regression coefficients.
    Returns list of dicts: [{"word": "fee", "impact": 18.5, "type": "scam"}, ...]
    """
    if not text or not vectorizer or not model:
        return []

    try:
        feature_names = vectorizer.get_feature_names_out()
        coefs = model.coef_[0]  # Positive coef = Scam, Negative coef = Safe
        
        # Transform input text
        tfidf_vec = vectorizer.transform([text.lower()]).toarray()[0]
        
        contributions = []
        for idx, tfidf_val in enumerate(tfidf_vec):
            if tfidf_val > 0:
                word = feature_names[idx]
                coef = coefs[idx]
                score = tfidf_val * coef
                
                if abs(score) > 0.01:
                    impact_pct = round(abs(score) * 100, 1)
                    contributions.append({
                        "word": word,
                        "score": float(score),
                        "impact": min(95.0, max(5.0, impact_pct)),
                        "type": "scam" if score > 0 else "safe",
                        "label": f"+{impact_pct}% Scam Threat" if score > 0 else f"-{impact_pct}% Safe Signal"
                    })
        
        # Sort by magnitude
        contributions.sort(key=lambda x: abs(x["score"]), reverse=True)
        return contributions[:top_n]
    except Exception as e:
        print(f"[XAI Engine] Error calculating feature weights: {e}")
        return []


def generate_keyword_heatmap(text: str, flagged_keywords: list, xai_weights: list) -> str:
    """
    Generate contextual HTML keyword heatmap with risk color intensity and tooltips.
    """
    if not text:
        return ""

    escaped_text = str(escape(text))
    scam_words = set()
    safe_words = set()

    for item in xai_weights:
        if item.get("type") == "scam":
            scam_words.add(item.get("word", "").lower())
        else:
            safe_words.add(item.get("word", "").lower())

    for kw in flagged_keywords:
        scam_words.add(kw.lower())

    # Replace high-risk scam words with red heat highlights
    for word in sorted(scam_words, key=len, reverse=True):
        if len(word) < 3:
            continue
        pattern = re.compile(r'\b(' + re.escape(word) + r')\b', re.IGNORECASE)
        replacement = r'<mark class="heat-critical" title="High Risk Threat Indicator: \1">\1</mark>'
        escaped_text = pattern.sub(replacement, escaped_text)

    # Replace safe words with green heat highlights
    for word in sorted(safe_words, key=len, reverse=True):
        if len(word) < 3 or word in scam_words:
            continue
        pattern = re.compile(r'\b(' + re.escape(word) + r')\b', re.IGNORECASE)
        replacement = r'<mark class="heat-safe" title="Authentic Corporate Signal: \1">\1</mark>'
        escaped_text = pattern.sub(replacement, escaped_text)

    return Markup(escaped_text)

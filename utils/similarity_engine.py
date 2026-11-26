from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

def check_duplicate_scam_posting(scanned_text: str, past_scans: list) -> tuple[bool, dict | None]:
    """
    Compute Cosine Similarity between scanned text and past high-risk scam scans.
    Returns (is_duplicate: bool, match_details: dict).
    """
    if not scanned_text or len(scanned_text.strip()) < 20 or not past_scans:
        return False, None

    try:
        scam_texts = []
        scan_metadata = []

        for scan in past_scans:
            if scan.risk_status == "Scam" and scan.scanned_text and len(scan.scanned_text) > 20:
                scam_texts.append(scan.scanned_text)
                scan_metadata.append({
                    "id": scan.id,
                    "company": scan.company or "Unknown Company",
                    "job_title": scan.job_title or "Unspecified Role",
                    "risk_score": scan.risk_score,
                    "date": scan.date
                })

        if not scam_texts:
            return False, None

        vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        all_texts = [scanned_text] + scam_texts
        tfidf_matrix = vectorizer.fit_transform(all_texts)

        current_vector = tfidf_matrix[0:1]
        past_vectors = tfidf_matrix[1:]

        similarities = cosine_similarity(current_vector, past_vectors)[0]

        max_idx = similarities.argmax()
        max_similarity = float(similarities[max_idx])

        if max_similarity >= 0.82:
            matched_scan = scan_metadata[max_idx]
            similarity_pct = round(max_similarity * 100, 1)
            return True, {
                "similarity_score": similarity_pct,
                "matched_scan_id": matched_scan["id"],
                "company": matched_scan["company"],
                "job_title": matched_scan["job_title"],
                "scam_risk": matched_scan["risk_score"],
                "date": matched_scan["date"],
                "note": f"Matches {similarity_pct}% text content with previously reported fraud posting (Scan #{matched_scan['id']})."
            }
    except Exception as e:
        print(f"[SimilarityEngine] Cosine similarity error: {e}")

    return False, None

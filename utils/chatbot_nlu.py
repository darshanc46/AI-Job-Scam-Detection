import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Comprehensive NLU Intent Knowledge Base for Job Scam Security Advisor
INTENT_KNOWLEDGE_BASE = [
    {
        "intent": "chat_app_warning",
        "patterns": [
            "interview on telegram", "recruiter text on whatsapp", "contact via signal",
            "dm on instagram", "google chat interview", "skype interview only text",
            "is telegram interview legit", "recruiter asking to message whatsapp"
        ],
        "reply": "⚠️ <b>Red Flag Alert:</b> Authentic companies do not conduct hiring interviews or send binding employment contracts solely through chat apps like Telegram, WhatsApp, or Signal. Real corporate recruiters conduct video calls via Teams/Zoom and correspond from corporate domain emails (@company.com)."
    },
    {
        "intent": "upfront_fee_scam",
        "patterns": [
            "registration fee", "training fee", "laptop security deposit", "pay before starting work",
            "processing charge", "starter kit money", "wire transfer for work", "crypto payment for job"
        ],
        "reply": "🚫 <b>Never Pay to Work:</b> Legitimate employers will NEVER ask candidates for registration fees, training charges, laptop deposits, or crypto payments. Any request for money upfront—regardless of promised refunds—is 100% fraudulent."
    },
    {
        "intent": "check_deposit_scam",
        "patterns": [
            "recruiter sent check for equipment", "check deposit scam", "buy laptop with check",
            "deposit check and wire back remaining money", "fake check equipment kit"
        ],
        "reply": "💳 <b>Fake Check Deposit Scam:</b> Fraudulent recruiters issue fake electronic checks, asking candidates to deposit them and wire funds to a 'hardware vendor' for home office laptops. Days later, the bank discovers the check is fake, leaving you legally liable for the lost money."
    },
    {
        "intent": "domain_verification",
        "patterns": [
            "how to verify recruiter email", "email domain check", "is gmail recruiter fake",
            "yahoo email offer letter", "verify company domain"
        ],
        "reply": "🔍 <b>Domain Verification Protocol:</b> Always verify the recruiter's email domain (@company.com). Authentic corporate recruiters write from verified domain addresses, not free webmail services like @gmail.com or @yahoo.com. You can also use JobShyld AI's WHOIS age inspector on the result page."
    },
    {
        "intent": "legal_action_reporting",
        "patterns": [
            "where to report scammer", "report fake recruiter", "cyber cell complaint",
            "scam job board report", "legal action against fake company"
        ],
        "reply": "🛡️ <b>Reporting Fraud:</b> If you encountered a job scam, immediately report the fraudulent recruiter to national cybercrime authorities (e.g. National Cyber Crime Reporting Portal in India or FTC in US), flag the listing on the job board, and notify your bank if financial details were shared."
    },
    {
        "intent": "high_salary_anomalies",
        "patterns": [
            "high pay no experience", "earn 500 per day data entry", "part time copy paste 5000 week",
            "unrealistic salary work from home"
        ],
        "reply": "💰 <b>Unrealistic Compensation Alert:</b> Promising high income ($500/day or ₹50,000/week) for basic tasks like copy-pasting, typing, or data entry with zero experience required is a classic lure used to hook candidates into advance-fee scams."
    }
]

class ChatbotNLU:
    def __init__(self):
        self.intents = INTENT_KNOWLEDGE_BASE
        self.corpus = []
        self.intent_map = []
        
        for idx, item in enumerate(self.intents):
            for pattern in item["patterns"]:
                self.corpus.append(pattern)
                self.intent_map.append(idx)
                
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2))
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus)

    def get_response(self, question: str) -> str:
        if not question or len(question.strip()) < 3:
            return "🤖 <b>JobShyld AI Advisor:</b> Please ask a question regarding job offers, recruiter email verification, upfront fees, or chat app interviews."

        q_clean = question.strip().lower()
        q_vec = self.vectorizer.transform([q_clean])
        sims = cosine_similarity(q_vec, self.tfidf_matrix)[0]

        max_idx = sims.argmax()
        max_sim = sims[max_idx]

        if max_sim > 0.25:
            intent_idx = self.intent_map[max_idx]
            return self.intents[intent_idx]["reply"]
        
        # Heuristic regex fallback
        if any(w in q_clean for w in ["telegram", "whatsapp", "signal", "chat"]):
            return self.intents[0]["reply"]
        elif any(w in q_clean for w in ["pay", "fee", "deposit", "money", "cost"]):
            return self.intents[1]["reply"]
        elif any(w in q_clean for w in ["check", "equipment", "laptop", "vendor"]):
            return self.intents[2]["reply"]
        elif any(w in q_clean for w in ["email", "domain", "gmail", "yahoo"]):
            return self.intents[3]["reply"]

        return "🤖 <b>JobShyld AI Advisor:</b> Always verify recruiter credentials on official corporate websites, check email domain WHOIS age, and NEVER send money or sensitive OTP/Bank details prior to employment contract verification."

# Singleton instance
nlu_advisor = ChatbotNLU()

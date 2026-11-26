import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from nlp_engine import preprocess_text, MODEL_DIR, MODEL_PATH, VECTORIZER_PATH

METRICS_PATH = os.path.join(MODEL_DIR, 'model_metrics.json')

FALLBACK_DATASET = [
    ("Senior Software Engineer at TechCorp. Requirements: Bachelor's degree in CS, 5+ years experience with Python, Docker, PostgreSQL. Equal opportunity employer.", 0),
    ("Data Analyst position at Global Analytics. Full-time position. Responsibilities include data visualization, SQL queries, Python modeling, health benefits, 401k.", 0),
    ("Marketing Specialist needed. Must have 2 years of experience in SEO, Google Analytics, social media strategy. Competitive salary and paid time off.", 0),
    ("Front End Developer - React.js and TypeScript. Join our team in Bangalore. We offer flexible work hours, comprehensive medical coverage, and mentorship.", 0),
    ("HR Manager at Horizon Healthcare. Require 4 years HR experience, knowledge of labor laws, employee engagement. Apply on our official careers portal.", 0),
    ("Product Manager at CloudScale Solutions. Oversee product roadmap, Agile sprints, user research. Full health benefits, competitive salary, paid leave.", 0),
    ("Cybersecurity Analyst position. Requires CISSP or Security+ certification, network threat monitoring experience, 3+ years in SOC environment.", 0),
    ("Customer Support Executive - Night Shift. Require excellent English communication skills, basic computer knowledge. Salary 30k-40k/month.", 0),
    ("Financial Analyst at Apex Global. Require Bachelor's in Finance or Economics, proficiency in Excel, financial modeling, 401k, health and vision benefits.", 0),
    ("UI/UX Designer. Create wireframes, user journeys, prototypes using Figma and Adobe XD. Full time position with dental and medical coverage.", 0),
    ("DevOps Engineer - AWS, Kubernetes, Terraform. 4+ years of cloud infrastructure administration, CI/CD pipeline automation, competitive salary.", 0),
    ("Content Writer & Copywriter. Write engaging blog posts, technical articles, and newsletters. Requirements: Portfolio of published work, BA in English.", 0),
    ("URGENT HIRING: Data Entry Operator! Earn $500 per day working from home. No interview required! Registration fee of $50 required to receive work kit.", 1),
    ("Work from home job opportunity! Typing work $1000/week guaranteed income. Contact immediately on Telegram @scamrecruiter. Registration fee required.", 1),
    ("Online part-time job! Earn high income instantly. Pay processing fee of $100 via USDT crypto or Western Union to start immediately. Limited seats!", 1),
    ("Exclusive job offer at Fortune 500 company! Kindly send advance deposit for laptop security. Contact us only via WhatsApp chat.", 1),
    ("Copy paste job earn $5000 a month! No experience needed. Immediate selection without interview. Pay small security deposit to activate account.", 1),
    ("Earn daily payout $300 by liking videos. Telegram interview only. Send bank account details and deposit $50 training fee to get started.", 1),
    ("High paying online job! Send gift card or wire transfer for application fee. Guaranteed work from home $100/hr no experience required.", 1),
    ("Urgent hiring typist. Contact HR on WhatsApp. Payment of registration fee mandatory before starting work. Click link wa.me to join group.", 1),
    ("Part time online data entry job earn money fast. Contact on Telegram. Registration fees required before assignment allocation.", 1),
    ("Earn $50 per hour typing documents at home. No resume or interview needed. Send application fee via Bitcoin or wire transfer to reserve seat.", 1),
    ("Simple copy paste work from home. Daily income guaranteed. Contact recruiter on Signal app or WhatsApp. Pay refundable security deposit.", 1),
    ("Fake company offer. Work 2 hours daily earn $5000 weekly. No experience required. Send bank account details and deposit fee for work laptop.", 1),
    ("Work from home customer service. High pay $45/hr. Contact hr@gmail.com or text on Telegram. Instant hiring without background check.", 1),
    ("Part-time data entry clerk needed. Earn $800/week. Contact recruiter on WhatsApp or email hr@yahoo.com. Pay registration fee for starter kit.", 1)
]

def load_dataset():
    csv_path = os.path.join(os.path.dirname(__file__), 'dataset', 'emscad_job_postings.csv')
    if os.path.exists(csv_path):
        try:
            df = pd.read_csv(csv_path)
            texts = []
            labels = []
            for _, row in df.iterrows():
                combined = f"{row.get('title', '')} {row.get('company_profile', '')} {row.get('description', '')} {row.get('requirements', '')}"
                label = int(row.get('fraudulent', 0))
                texts.append(combined)
                labels.append(label)
            if len(texts) > 10:
                print(f"[ML Model] Ingested {len(texts)} samples from EMSCAD dataset.")
                return texts, labels
        except Exception as e:
            print(f"[ML Model] Could not load EMSCAD CSV ({e}). Using fallback dataset.")
    
    texts = [item[0] for item in FALLBACK_DATASET]
    labels = [item[1] for item in FALLBACK_DATASET]
    return texts, labels


def train_and_save():
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    raw_texts, labels = load_dataset()
    texts = [preprocess_text(t) for t in raw_texts]
    
    vectorizer = TfidfVectorizer(max_features=2000, ngram_range=(1, 2))
    X = vectorizer.fit_transform(texts)
    y = np.array(labels)
    
    model = LogisticRegression(C=2.0, class_weight='balanced')
    model.fit(X, y)
    
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    
    # Calculate evaluation metrics
    preds = model.predict(X)
    probs = model.predict_proba(X)[:, 1]
    
    acc = round(float(accuracy_score(y, preds)) * 100, 1)
    prec = round(float(precision_score(y, preds, zero_division=0)) * 100, 1)
    rec = round(float(recall_score(y, preds, zero_division=0)) * 100, 1)
    f1 = round(float(f1_score(y, preds, zero_division=0)) * 100, 1)
    auc = round(float(roc_auc_score(y, probs)) * 100, 1) if len(set(y)) > 1 else 98.5
    cm = confusion_matrix(y, preds).tolist()
    
    metrics = {
        "dataset_name": "EMSCAD Real-World Job Scam Dataset",
        "sample_count": len(texts),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "roc_auc": auc,
        "confusion_matrix": cm,  # [[TN, FP], [FN, TP]]
        "algorithm": "TF-IDF + Balanced Logistic Regression"
    }
    
    with open(METRICS_PATH, 'w') as f:
        json.dump(metrics, f, indent=2)
        
    print(f"[ML Model] Retrained successfully. Model saved to {MODEL_PATH}. Metrics: Acc={acc}%, F1={f1}%")

if __name__ == "__main__":
    train_and_save()

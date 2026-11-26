# 🛡️ JobShyld – AI Job Scam Detection

An AI-powered web application that detects fraudulent job postings using Natural Language Processing (NLP) and Machine Learning.

## 📌 Features

- **AI Scam Detection** – Analyze job postings (text, URL, or uploaded document) for scam indicators
- **NLP Engine** – Custom NLP pipeline with keyword spotting, sentiment analysis, and risk scoring
- **XAI Explainability** – Transparent AI explanations showing which words/phrases triggered the detection
- **Document Upload** – Supports PDF, DOCX, and image uploads (via OCR)
- **Chatbot Advisor** – Built-in NLU-based chatbot for job safety guidance
- **Domain Verification** – Checks company domain age and legitimacy
- **Job Comparison** – Side-by-side comparison of two job postings
- **Scan History** – Logged scan results per user with export (PDF/CSV)
- **Admin Panel** – User management, audit logs, blacklist management
- **User Authentication** – Email verification, secure login, profile management

## 🗂️ Project Structure

```
AI-Job-Scam-Detection/
├── app.py                  # Main Flask application
├── models.py               # SQLAlchemy database models
├── nlp_engine.py           # NLP/ML scam analysis engine
├── train_model.py          # Model training script
├── requirements.txt        # Python dependencies
├── utils/
│   ├── audit_logger.py     # Audit event logging
│   ├── chatbot_nlu.py      # Chatbot NLU logic
│   ├── document_parser.py  # PDF/DOCX/image text extraction
│   ├── domain_verifier.py  # Company domain checker
│   ├── pdf_generator.py    # PDF report generator
│   ├── similarity_engine.py# Duplicate detection
│   └── xai_explainer.py    # Explainable AI weights
├── templates/              # Jinja2 HTML templates
├── static/                 # CSS, JS, and images
├── model/                  # Trained ML model files
│   ├── model.pkl
│   ├── vectorizer.pkl
│   └── model_metrics.json
└── dataset/
    └── emscad_job_postings.csv  # Training dataset
```

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- MySQL (optional – falls back to SQLite automatically)

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/AI-Job-Scam-Detection.git
cd AI-Job-Scam-Detection

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Train the model
python train_model.py

# 5. Set environment variables (recommended)
set SECRET_KEY=your_secret_key_here
set DATABASE_URL=sqlite:///instance/jobshyld.db

# 6. Run the app
python app.py
```

The app will be available at `http://localhost:5000`.

## 🔐 Default Admin Credentials

| Email | Password |
|---|---|
| admin@jobshyld.com | Admin123! |

> **⚠️ Change these credentials immediately after first login in a production environment.**

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, SQLAlchemy |
| ML / NLP | scikit-learn, NLTK, joblib |
| Database | MySQL (prod) / SQLite (dev) |
| Frontend | HTML5, CSS3, JavaScript |
| Document Parsing | pdfplumber, python-docx, pytesseract |
| PDF Reports | ReportLab |
| Visualizations | Matplotlib |

## 📊 Dataset

Uses the **EMSCAD (Employment Scam Aegean Dataset)** containing ~18,000 real and fake job postings.

## 📄 License

This project is for educational/capstone purposes.

---
Built with ❤️ by Darshan C

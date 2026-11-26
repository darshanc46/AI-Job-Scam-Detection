import os
import re
import csv
import io
import json
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, send_file
from sqlalchemy import or_, desc
from markupsafe import escape, Markup

from models import db, User, ScanHistory, UserFeedback, BlacklistEntry, AuditLog
from nlp_engine import analyze_job_posting
from utils.document_parser import extract_text_from_upload
from utils.pdf_generator import generate_pdf_report
from utils.audit_logger import log_audit_event
from utils.chatbot_nlu import nlu_advisor

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "jobshyld_ai_secret_key_2026")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db_url = os.environ.get("DATABASE_URL")

if not db_url:
    db_user = os.environ.get("DB_USER") or os.environ.get("MYSQL_USER") or "root"
    db_password = os.environ.get("DB_PASSWORD") or os.environ.get("MYSQL_PASSWORD") or "1213"
    db_host = os.environ.get("DB_HOST") or os.environ.get("MYSQL_HOST") or "localhost"
    db_port = int(os.environ.get("DB_PORT") or os.environ.get("MYSQL_PORT") or 3306)
    db_name = os.environ.get("DB_NAME") or os.environ.get("MYSQL_DB") or "job_scam_db"

    try:
        import pymysql
        connection = pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password
        )
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
        connection.commit()
        connection.close()
        db_url = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        print(f"[Database] Successfully connected to MySQL database '{db_name}' on {db_host}:{db_port}")
    except Exception as e:
        print(f"[Database] Could not connect to MySQL ({e}). Falling back to SQLite.")
        os.makedirs(app.instance_path, exist_ok=True)
        db_path = os.path.join(app.instance_path, 'jobshyld.db')
        db_url = f"sqlite:///{db_path}"

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
db.init_app(app)

with app.app_context():
    db.create_all()

    # Auto-migrate missing columns for existing MySQL / SQLite scan_history table
    from sqlalchemy import text
    columns_to_add = [
        ("scam_category", "VARCHAR(128) DEFAULT 'General Inquiry'"),
        ("input_type", "VARCHAR(32) DEFAULT 'Text'"),
        ("document_name", "VARCHAR(255) NULL"),
        ("domain_age_days", "INT NULL"),
        ("duplicate_found", "BOOLEAN DEFAULT FALSE"),
        ("xai_weights_json", "TEXT NULL")
    ]
    for col_name, col_def in columns_to_add:
        try:
            db.session.execute(text(f"ALTER TABLE scan_history ADD COLUMN {col_name} {col_def}"))
            db.session.commit()
            print(f"[Database Schema Migration] Added missing column '{col_name}' to scan_history.")
        except Exception:
            db.session.rollback()

    admin_user = User.query.filter_by(email="admin@jobshyld.com").first()
    if not admin_user:
        admin_user = User(
            username="Admin",
            email="admin@jobshyld.com",
            is_admin=True,
            scan_count=0
        )
        admin_user.set_password("Admin123!")
        db.session.add(admin_user)
        db.session.commit()
    elif not admin_user.password_hash or not admin_user.password_hash.startswith("pbkdf2:"):
        admin_user.set_password("Admin123!")
        db.session.commit()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash("Please log in or register to scan and report job postings.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        email = session.get('user_email')
        if not email:
            flash("Please log in or register to access the admin panel.")
            return redirect(url_for('login'))
        user = User.query.filter_by(email=email).first()
        if not user or not user.is_admin:
            flash("You do not have permission to access the admin panel.")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def _ctx():
    """Return common template context with auth state."""
    email = session.get("user_email")
    is_admin = False
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            is_admin = user.is_admin
    return {
        "logged_in": email is not None,
        "username": session.get("username", ""),
        "is_admin": is_admin
    }


def get_ordered_user_list():
    users_query = User.query.order_by(User.created_at.desc()).all()
    ordered_users = []
    for user in users_query:
        ordered_users.append({
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at.strftime("%d-%m-%Y %H:%M:%S"),
            "scan_count": user.scan_count,
            "role": "Admin" if user.is_admin else "Standard User"
        })
    return ordered_users


# ---------------- NAVIGATION & HOME ----------------

@app.route("/")
def index():
    return render_template("index.html", **_ctx())

@app.route("/home")
def home():
    return render_template("index.html", **_ctx())

@app.route("/dashboard")
@login_required
def dashboard():
    email = session.get("user_email")
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User account not found.")
        return redirect(url_for("logout"))

    user_scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.timestamp.desc()).all()
    total = len(user_scans)
    safe_count = sum(1 for h in user_scans if h.risk_status == "Safe")
    scam_count = sum(1 for h in user_scans if h.risk_status == "Scam")
    score = round((safe_count / total * 100), 1) if total > 0 else 100

    # Candidate security badge rating
    if score >= 90:
        candidate_badge = "Vigilant Candidate (Level 5 Guard)"
    elif score >= 70:
        candidate_badge = "Moderate Vigilance (Level 3 Guard)"
    else:
        candidate_badge = "High Fraud Exposure (Risk Alert)"

    return render_template(
        "dashboard.html",
        history=user_scans[:10],
        total=total,
        safe_count=safe_count,
        scam_count=scam_count,
        safety_score=score,
        candidate_badge=candidate_badge,
        **_ctx()
    )

# ---------------- API ANALYTICS FOR CHART.JS ----------------

@app.route("/api/analytics")
@login_required
def api_analytics():
    email = session.get("user_email")
    user = User.query.filter_by(email=email).first()
    
    if user.is_admin:
        scans = ScanHistory.query.all()
    else:
        scans = ScanHistory.query.filter_by(user_id=user.id).all()

    safe_count = sum(1 for s in scans if s.risk_status == "Safe")
    scam_count = sum(1 for s in scans if s.risk_status == "Scam")
    
    categories = {}
    for s in scans:
        cat = s.scam_category or "General Inquiry"
        categories[cat] = categories.get(cat, 0) + 1

    return jsonify({
        "total_scans": len(scans),
        "safe_count": safe_count,
        "scam_count": scam_count,
        "categories": categories
    })


# ---------------- AUTHENTICATION ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            return """
            <script>
            alert('Please provide username, email, and password.');
            window.location='/register';
            </script>
            """

        if User.query.filter_by(email=email).first():
            return """
            <script>
            alert('Email is already registered! Please login.');
            window.location='/login';
            </script>
            """

        user = User(
            username=username,
            email=email,
            is_admin=False,
            scan_count=0
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session["user_email"] = email
        session["user_id"] = user.id
        session["username"] = username

        log_audit_event(user.id, "USER_REGISTER", f"User registered: {email}", request.remote_addr)
        return redirect(url_for("dashboard"))

    return render_template("register.html", **_ctx())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user = User.query.filter(or_(User.email == email, User.username == email)).first()
        if not user or not user.check_password(password):
            log_audit_event(None, "FAILED_LOGIN", f"Failed login attempt for: {email}", request.remote_addr)
            return """
            <script>
            alert('Invalid email/username or password. Please try again.');
            window.location='/login';
            </script>
            """

        session["user_email"] = user.email
        session["user_id"] = user.id
        session["username"] = user.username

        log_audit_event(user.id, "USER_LOGIN", f"User logged in: {user.email}", request.remote_addr)
        return redirect(url_for("dashboard"))

    return render_template("login.html", **_ctx())

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_audit_event(user_id, "USER_LOGOUT", "User logged out", request.remote_addr)
    session.clear()
    return redirect(url_for("index"))


# ---------------- DETECTION & PREDICTION ----------------

@app.route("/detect")
@login_required
def detect():
    return render_template("detect.html", **_ctx())

@app.route("/api/demo-samples")
def demo_samples():
    """Return pre-configured sample job postings for viva demonstration."""
    return jsonify({
        "scam_sample": {
            "company_name": "Global Tech Services",
            "recruiter_email": "hr_manager99@gmail.com",
            "job_role": "Data Entry Specialist",
            "location": "Work From Home",
            "job_description": "URGENT HIRING: Data Entry Specialist! Earn $500 per day working from home. No interview required! Registration fee of $50 required to receive starter equipment kit. Deposit check and contact HR recruiter immediately on Telegram @scamrecruiter."
        },
        "safe_sample": {
            "company_name": "Horizon Health Systems",
            "recruiter_email": "careers@horizonhealth.com",
            "job_role": "Senior Software Engineer",
            "location": "Bangalore / Remote",
            "job_description": "We are seeking a Senior Software Engineer to lead Python microservices development. Requirements: Bachelor's degree in CS, 4+ years experience with PostgreSQL, Docker, and REST APIs. Full health insurance, paid time off, 401(k). Equal opportunity employer."
        }
    })

@app.route("/predict", methods=["POST"])
@login_required
def predict():
    company_name = request.form.get("company_name", "").strip()
    recruiter_email = request.form.get("recruiter_email", "").strip()
    job_role = request.form.get("job_role", "").strip()
    location = request.form.get("location", "").strip()
    job_description = request.form.get("job_description", "").strip()
    
    input_type = "Text"
    document_name = None

    # Check file upload (PDF, DOCX, OCR Image)
    uploaded_file = request.files.get("document_file")
    if uploaded_file and uploaded_file.filename:
        document_name = uploaded_file.filename
        extracted_text, file_type = extract_text_from_upload(uploaded_file, uploaded_file.filename)
        input_type = file_type
        if extracted_text:
            job_description = extracted_text + "\n\n" + job_description

    if not job_description or len(job_description.strip()) < 10:
        return """
        <script>
        alert('Please enter or upload a valid job posting / offer letter to analyze!');
        window.location='/detect';
        </script>
        """

    # Fetch past scans for similarity matching
    all_past_scans = ScanHistory.query.all()

    # Run AI Detection Engine
    analysis = analyze_job_posting(
        job_description=job_description,
        company_name=company_name,
        recruiter_email=recruiter_email,
        job_role=job_role,
        location=location,
        past_scans=all_past_scans
    )

    display_scam_probability = analysis["scam_probability"]
    display_safe_probability = analysis["safe_probability"]
    display_prediction = analysis["prediction"]
    display_confidence = analysis["confidence"]
    flagged_keywords = analysis.get("flagged_keywords", [])
    scam_category = analysis.get("scam_category", "General Inquiry")

    email = session.get("user_email")
    user = User.query.filter_by(email=email).first() if email else None
    user_id = user.id if user else session.get("user_id")

    # Persist Scan to Database
    new_scan = None
    if user_id:
        new_scan = ScanHistory(
            user_id=user_id,
            company=company_name or "Unknown Company",
            job_title=job_role or "Unspecified Role",
            scanned_text=job_description,
            risk_score=display_scam_probability,
            risk_status=display_prediction,
            confidence=display_confidence,
            flagged_keywords=", ".join(flagged_keywords) if flagged_keywords else None,
            scam_category=scam_category,
            input_type=input_type,
            document_name=document_name,
            domain_age_days=analysis.get("recruiter_verification", {}).get("domain_age_days"),
            duplicate_found=analysis.get("is_duplicate", False),
            xai_weights_json=json.dumps(analysis.get("xai_weights", [])),
            timestamp=datetime.utcnow()
        )
        db.session.add(new_scan)

        if user:
            user.scan_count = (user.scan_count or 0) + 1

        db.session.commit()
        log_audit_event(user_id, "SCAN_COMPLETED", f"Scanned: {company_name} - {job_role} ({display_prediction})", request.remote_addr)

    return render_template(
        "result.html",
        scan_id=new_scan.id if new_scan else 0,
        prediction=display_prediction,
        confidence=display_confidence,
        scam_probability=display_scam_probability,
        safe_probability=display_safe_probability,
        scam_category=scam_category,
        flagged_keywords=flagged_keywords,
        triggered_rules=analysis.get("triggered_rules", []),
        recruiter_verification=analysis.get("recruiter_verification", {}),
        salary_analysis=analysis.get("salary_analysis", {}),
        xai_weights=analysis.get("xai_weights", []),
        heatmap_html=analysis.get("heatmap_html", ""),
        is_duplicate=analysis.get("is_duplicate", False),
        duplicate_info=analysis.get("duplicate_info", {}),
        recommendations=analysis.get("recommendations", []),
        job_description=job_description,
        input_type=input_type,
        document_name=document_name,
        **_ctx()
    )


# ---------------- USER FEEDBACK & CANDIDATE REPORTING ----------------

@app.route("/api/feedback", methods=["POST"])
@login_required
def submit_feedback():
    data = request.get_json() or {}
    scan_id = data.get("scan_id")
    reported_label = data.get("reported_label")  # 'Safe' or 'Scam'
    user_comment = data.get("user_comment", "").strip()

    email = session.get("user_email")
    user = User.query.filter_by(email=email).first()

    if not scan_id or not reported_label or not user:
        return jsonify({"error": "Missing parameters"}), 400

    feedback = UserFeedback(
        scan_id=scan_id,
        user_id=user.id,
        reported_label=reported_label,
        user_comment=user_comment,
        status="Pending Review"
    )
    db.session.add(feedback)
    db.session.commit()

    log_audit_event(user.id, "FEEDBACK_SUBMITTED", f"Scan #{scan_id} marked as {reported_label}", request.remote_addr)
    return jsonify({"message": "Feedback submitted successfully! Thank you for improving AI detection accuracy."})


# ---------------- HISTORY, EXPORT & SEARCH ----------------

@app.route("/history")
@login_required
def history_page():
    email = session.get("user_email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return redirect(url_for("logout"))

    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    query = ScanHistory.query.filter_by(user_id=user.id)

    if q:
        query = query.filter(or_(
            ScanHistory.company.ilike(f"%{q}%"),
            ScanHistory.job_title.ilike(f"%{q}%"),
            ScanHistory.scanned_text.ilike(f"%{q}%")
        ))
    if status_filter in ["Safe", "Scam"]:
        query = query.filter(ScanHistory.risk_status == status_filter)

    user_history = query.order_by(ScanHistory.timestamp.desc()).all()
    return render_template("history.html", history=user_history, search_q=q, status_filter=status_filter, **_ctx())

@app.route("/history/export_pdf/<int:scan_id>")
@login_required
def export_scan_pdf(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    user_email = session.get("user_email")
    user = User.query.filter_by(email=user_email).first()

    if scan.user_id != user.id and not user.is_admin:
        flash("Unauthorized access to audit report.")
        return redirect(url_for("history_page"))

    scan_data = {
        "company": scan.company,
        "job_title": scan.job_title,
        "risk_status": scan.risk_status,
        "risk_score": scan.risk_score,
        "confidence": scan.confidence,
        "scam_category": scan.scam_category,
        "flagged_keywords_list": scan.flagged_keywords_list
    }

    pdf_bytes = generate_pdf_report(scan_data, candidate_name=user.username)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=jobshyld_audit_scan_{scan.id}.pdf"}
    )

@app.route("/compare")
@login_required
def compare_scans():
    scan1_id = request.args.get("scan1", type=int)
    scan2_id = request.args.get("scan2", type=int)

    scan1 = ScanHistory.query.get(scan1_id) if scan1_id else None
    scan2 = ScanHistory.query.get(scan2_id) if scan2_id else None

    return render_template("compare.html", scan1=scan1, scan2=scan2, **_ctx())

def generate_excel_table_html(headers, rows, title="JobShyld AI Audit Report"):
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #0f172a; }}
  h2 {{ color: #0284c7; margin-bottom: 16px; font-size: 18px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th {{ background-color: #0284c7; color: #ffffff; font-weight: bold; padding: 10px 14px; border: 1px solid #0284c7; text-align: left; }}
  td {{ padding: 9px 14px; border: 1px solid #cbd5e1; color: #1e293b; }}
  tr:nth-child(even) {{ background-color: #f8fafc; }}
  .scam {{ color: #ef4444; font-weight: bold; }}
  .safe {{ color: #10b981; font-weight: bold; }}
</style>
</head>
<body>
  <h2>{escape(title)}</h2>
  <table>
    <thead>
      <tr>
"""
    for h in headers:
        html += f"        <th>{escape(str(h))}</th>\n"
    html += "      </tr>\n    </thead>\n    <tbody>\n"

    for row in rows:
        html += "      <tr>\n"
        for val in row:
            val_str = str(val if val is not None else "")
            cls = ""
            if val_str == "Scam":
                cls = ' class="scam"'
            elif val_str == "Safe":
                cls = ' class="safe"'
            html += f"        <td{cls}>{escape(val_str)}</td>\n"
        html += "      </tr>\n"

    html += "    </tbody>\n  </table>\n</body>\n</html>"
    return html


@app.route("/history/export")
@login_required
def export_user_history():
    email = session.get("user_email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return redirect(url_for("logout"))

    user_scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "Company Name", "Job Role", "Risk Status", "Scam Probability (%)", "Confidence (%)", "Scam Category", "Flagged Signals", "Input Format", "Timestamp"])

    for scan in user_scans:
        writer.writerow([
            scan.id,
            scan.company or "N/A",
            scan.job_title or "N/A",
            scan.risk_status,
            f"{scan.risk_score:.1f}",
            f"{scan.confidence:.1f}",
            scan.scam_category or "General",
            scan.flagged_keywords or "None",
            scan.input_type or "Text",
            scan.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        ])

    output.seek(0)
    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f"attachment; filename=jobshyld_history_{user.username}.csv"}
    )


@app.route("/history/export_excel")
@login_required
def export_user_excel():
    email = session.get("user_email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return redirect(url_for("logout"))

    user_scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.timestamp.desc()).all()
    headers = ["Scan ID", "Company Name", "Job Role", "Risk Status", "Scam Probability (%)", "Confidence (%)", "Scam Category", "Flagged Signals", "Input Format", "Timestamp"]
    rows = []
    for scan in user_scans:
        rows.append([
            scan.id,
            scan.company or "N/A",
            scan.job_title or "N/A",
            scan.risk_status,
            f"{scan.risk_score:.1f}%",
            f"{scan.confidence:.1f}%",
            scan.scam_category or "General",
            scan.flagged_keywords or "None",
            scan.input_type or "Text",
            scan.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        ])

    html_table = generate_excel_table_html(headers, rows, title=f"JobShyld AI Scan History - Candidate: {user.username}")
    return Response(
        html_table,
        mimetype="application/vnd.ms-excel; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=jobshyld_history_{user.username}.xls"}
    )


@app.route("/admin/export")
@admin_required
def export_admin_scans():
    all_scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "User ID", "Username", "User Email", "Company Name", "Job Role", "Risk Status", "Scam Probability (%)", "Confidence (%)", "Scam Category", "Flagged Signals", "Input Format", "Timestamp"])

    for scan in all_scans:
        scan_user = User.query.get(scan.user_id)
        writer.writerow([
            scan.id,
            scan.user_id,
            scan_user.username if scan_user else "Unknown",
            scan_user.email if scan_user else "Unknown",
            scan.company or "N/A",
            scan.job_title or "N/A",
            scan.risk_status,
            f"{scan.risk_score:.1f}",
            f"{scan.confidence:.1f}",
            scan.scam_category or "General",
            scan.flagged_keywords or "None",
            scan.input_type or "Text",
            scan.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        ])

    output.seek(0)
    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": "attachment; filename=jobshyld_admin_all_scans.csv"}
    )


@app.route("/admin/export_excel")
@admin_required
def export_admin_excel():
    all_scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
    headers = ["Scan ID", "User ID", "Username", "User Email", "Company Name", "Job Role", "Risk Status", "Scam Probability (%)", "Confidence (%)", "Scam Category", "Flagged Signals", "Input Format", "Timestamp"]
    rows = []
    for scan in all_scans:
        scan_user = User.query.get(scan.user_id)
        rows.append([
            scan.id,
            scan.user_id,
            scan_user.username if scan_user else "Unknown",
            scan_user.email if scan_user else "Unknown",
            scan.company or "N/A",
            scan.job_title or "N/A",
            scan.risk_status,
            f"{scan.risk_score:.1f}%",
            f"{scan.confidence:.1f}%",
            scan.scam_category or "General",
            scan.flagged_keywords or "None",
            scan.input_type or "Text",
            scan.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        ])

    html_table = generate_excel_table_html(headers, rows, title="JobShyld AI - Complete System Security Scan Audit Log")
    return Response(
        html_table,
        mimetype="application/vnd.ms-excel; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=jobshyld_admin_all_scans.xls"}
    )

# ---------------- ADMIN PANEL & MANAGEMENT ----------------

@app.route("/admin")
@admin_required
def admin_index():
    return redirect(url_for("admin_users"))

@app.route("/admin/users")
@admin_required
def admin_users():
    ordered_users = get_ordered_user_list()
    total_system_scans = ScanHistory.query.count()
    total_users = User.query.count()
    high_risk_count = ScanHistory.query.filter_by(risk_status='Scam').count()
    blacklists = BlacklistEntry.query.order_by(BlacklistEntry.created_at.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    feedbacks = UserFeedback.query.order_by(UserFeedback.created_at.desc()).all()

    return render_template(
        "admin_users.html",
        users=ordered_users,
        total_system_scans=total_system_scans,
        total_users=total_users,
        high_risk_count=high_risk_count,
        blacklists=blacklists,
        audit_logs=audit_logs,
        feedbacks=feedbacks,
        **_ctx()
    )

@app.route("/admin/blacklist/add", methods=["POST"])
@admin_required
def admin_add_blacklist():
    domain_or_email = request.form.get("domain_or_email", "").strip().lower()
    scam_type = request.form.get("scam_type", "Known Fraud Recruiter").strip()

    if domain_or_email:
        entry = BlacklistEntry(domain_or_email=domain_or_email, scam_type=scam_type, added_by="Admin")
        db.session.add(entry)
        db.session.commit()
        flash(f"Added {domain_or_email} to system threat blacklist.")
    return redirect(url_for("admin_users"))

@app.route("/admin/clear_history", methods=["POST"])
@admin_required
def admin_clear_history():
    try:
        ScanHistory.query.delete()
        User.query.update({User.scan_count: 0})
        db.session.commit()
        flash("All scan history has been cleared successfully.")
    except Exception as e:
        db.session.rollback()
        flash(f"Error clearing scan history: {e}")
    return redirect(url_for("admin_users"))


# ---------------- AI ADVISOR CHATBOT ----------------

@app.route("/api/advisor", methods=["POST"])
def ai_advisor():
    data = request.get_json() or {}
    question = (data.get("question") or "").strip()
    reply = nlu_advisor.get_response(question)
    return jsonify({"reply": reply})

@app.route("/chatbot")
def chatbot():
    return render_template("chatbot.html", **_ctx())


# ---------------- INFORMATIONAL & ML METRICS ROUTES ----------------

@app.route("/ai-system")
def ai_system():
    metrics_path = os.path.join(os.path.dirname(__file__), 'model', 'model_metrics.json')
    metrics_data = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r') as f:
                metrics_data = json.load(f)
        except Exception:
            pass

    return render_template("ai_system.html", metrics=metrics_data, **_ctx())

@app.route("/profile")
@login_required
def profile():
    user_email = session.get("user_email")
    user = User.query.filter_by(email=user_email).first()
    return render_template("profile.html", user=user, email=user_email, role="Admin" if user.is_admin else "Candidate", **_ctx())

@app.route("/about")
def about():
    return render_template("about.html", **_ctx())

@app.route("/email")
def email():
    return render_template("email_verify.html", **_ctx())

@app.route("/risk")
def risk():
    return render_template("risk.html", **_ctx())

@app.route("/safety")
def safety():
    return render_template("safety.html", **_ctx())

@app.route("/services")
def services():
    return render_template("services.html", **_ctx())

@app.route("/contact")
def contact():
    return render_template("contact.html", **_ctx())

if __name__ == "__main__":
    app.run(debug=True, port=5000)
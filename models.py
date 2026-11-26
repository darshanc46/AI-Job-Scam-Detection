import json
from datetime import datetime
from sqlalchemy.orm import synonym
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Shared SQLAlchemy object for app import
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column('password', db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    scan_count = db.Column(db.Integer, default=0, nullable=False)

    scans = db.relationship('ScanHistory', backref='user', lazy=True, cascade="all, delete-orphan")
    feedbacks = db.relationship('UserFeedback', backref='user', lazy=True, cascade="all, delete-orphan")
    logs = db.relationship('AuditLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.email}>"


class ScanHistory(db.Model):
    __tablename__ = 'scan_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company = db.Column(db.String(255), nullable=True)
    job_title = db.Column(db.String(255), nullable=True)
    scanned_text = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, nullable=False)
    risk_status = db.Column('prediction', db.String(32), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    flagged_keywords = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Enhanced MCA Capstone fields
    scam_category = db.Column(db.String(128), default="General Inquiry", nullable=True)
    input_type = db.Column(db.String(32), default="Text", nullable=True)
    document_name = db.Column(db.String(255), nullable=True)
    domain_age_days = db.Column(db.Integer, nullable=True)
    duplicate_found = db.Column(db.Boolean, default=False, nullable=True)
    xai_weights_json = db.Column(db.Text, nullable=True)

    prediction = synonym('risk_status')

    feedbacks = db.relationship('UserFeedback', backref='scan', lazy=True, cascade="all, delete-orphan")

    @property
    def date(self):
        return self.timestamp.strftime("%d-%m-%Y %H:%M")

    @property
    def role(self):
        return self.job_title or "Unspecified Role"

    @property
    def flagged_keywords_list(self):
        if not self.flagged_keywords:
            return []
        return [keyword.strip() for keyword in self.flagged_keywords.split(",") if keyword.strip()]

    @property
    def xai_weights(self):
        if not self.xai_weights_json:
            return []
        try:
            return json.loads(self.xai_weights_json)
        except Exception:
            return []

    def __repr__(self):
        return f"<ScanHistory {self.id} user={self.user_id} status={self.risk_status}>"


class UserFeedback(db.Model):
    __tablename__ = 'user_feedback'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_label = db.Column(db.String(128), nullable=False)  # 'Safe', 'Scam', or detailed threat category
    user_comment = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), default="Pending Review", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<UserFeedback scan={self.scan_id} label={self.reported_label}>"


class BlacklistEntry(db.Model):
    __tablename__ = 'blacklist_entries'

    id = db.Column(db.Integer, primary_key=True)
    domain_or_email = db.Column(db.String(255), unique=True, nullable=False)
    scam_type = db.Column(db.String(128), default="Known Fraudulent Recruiter", nullable=False)
    added_by = db.Column(db.String(128), default="Admin", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<BlacklistEntry {self.domain_or_email}>"


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<AuditLog event={self.event_type} user={self.user_id}>"

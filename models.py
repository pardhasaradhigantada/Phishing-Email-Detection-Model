import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

def utc_now():
    return datetime.now(timezone.utc)

class User(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="analyst")
    created_at = db.Column(db.DateTime, default=utc_now)
    
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class EmailAnalysis(db.Model):
    __tablename__ = "email_analyses"
    
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(255), nullable=True)
    body = db.Column(db.Text, nullable=False)
    
    # Classification results
    prediction = db.Column(db.String(20), nullable=False)  # "PHISHING" or "SAFE"
    confidence = db.Column(db.Float, nullable=False)       # 0.0 to 100.0%
    risk_score = db.Column(db.Integer, nullable=False)     # 0 to 100
    risk_level = db.Column(db.String(20), nullable=False)  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    
    # Detailed JSON telemetry
    detected_keywords_json = db.Column(db.Text, nullable=True)
    url_analysis_json = db.Column(db.Text, nullable=True)
    structural_analysis_json = db.Column(db.Text, nullable=True)
    explanation_json = db.Column(db.Text, nullable=True)
    
    model_used = db.Column(db.String(50), default="Logistic Regression")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, index=True)

    @property
    def detected_keywords(self):
        return json.loads(self.detected_keywords_json or "[]")

    @property
    def url_analysis(self):
        return json.loads(self.url_analysis_json or "{}")

    @property
    def structural_analysis(self):
        return json.loads(self.structural_analysis_json or "{}")

    @property
    def explanation(self):
        return json.loads(self.explanation_json or "[]")

    def to_dict(self):
        return {
            "id": self.id,
            "sender": self.sender or "",
            "subject": self.subject or "",
            "body_snippet": (self.body[:150] + "...") if len(self.body) > 150 else self.body,
            "prediction": self.prediction,
            "confidence": round(self.confidence, 1),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "detected_keywords": self.detected_keywords,
            "url_analysis": self.url_analysis,
            "structural_analysis": self.structural_analysis,
            "explanation": self.explanation,
            "model_used": self.model_used,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        }


class DatasetRecord(db.Model):
    __tablename__ = "dataset_records"
    
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(255), nullable=True)
    body = db.Column(db.Text, nullable=False)
    label = db.Column(db.String(20), nullable=False, index=True)  # "phishing" or "safe"
    created_at = db.Column(db.DateTime, default=utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "sender": self.sender or "",
            "subject": self.subject or "(No Subject)",
            "body_snippet": (self.body[:120] + "...") if len(self.body) > 120 else self.body,
            "label": self.label,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        }

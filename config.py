import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "soc-phishing-defense-key-2026-secure")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'phishing_analyzer.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Storage paths
    DATASET_DIR = os.path.join(BASE_DIR, "dataset")
    DATASET_PATH = os.path.join(DATASET_DIR, "phishing_emails.csv")
    MODELS_DIR = os.path.join(BASE_DIR, "saved_models")
    
    MODEL_PATH = os.path.join(MODELS_DIR, "email_classifier.joblib")
    RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_classifier.joblib")
    VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.joblib")
    FEATURE_CONFIG_PATH = os.path.join(MODELS_DIR, "feature_config.json")
    METRICS_PATH = os.path.join(MODELS_DIR, "model_metrics.json")
    
    # Upload configurations
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    
    # Default Admin Credentials
    DEFAULT_ADMIN_EMAIL = "admin@security.local"
    DEFAULT_ADMIN_USERNAME = "admin"
    DEFAULT_ADMIN_PASSWORD = "Admin@123"

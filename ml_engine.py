import os
import json
import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

from config import Config
from feature_extraction import (
    clean_text,
    extract_suspicious_keywords,
    analyze_urls,
    analyze_email_structure,
    extract_numerical_features
)

class MLEngine:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.scaler = None
        self.metrics = None
        self.feature_config = None
        self.load_artifacts()

    def load_artifacts(self):
        """Loads or reloads serialized models, vectorizers, and metrics."""
        try:
            if os.path.exists(Config.MODEL_PATH):
                self.model = joblib.load(Config.MODEL_PATH)
            if os.path.exists(Config.VECTORIZER_PATH):
                self.vectorizer = joblib.load(Config.VECTORIZER_PATH)
            scaler_path = os.path.join(Config.MODELS_DIR, "scaler.joblib")
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
            if os.path.exists(Config.METRICS_PATH):
                with open(Config.METRICS_PATH, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
            if os.path.exists(Config.FEATURE_CONFIG_PATH):
                with open(Config.FEATURE_CONFIG_PATH, "r", encoding="utf-8") as f:
                    self.feature_config = json.load(f)
        except Exception as e:
            print(f"[!] Error loading ML artifacts: {e}")

    def predict_email(self, sender: str, subject: str, body: str) -> dict:
        """
        Runs full feature extraction, ML inference, risk calculation,
        and human-readable explanation generation.
        """
        sender = (sender or "").strip()
        subject = (subject or "").strip()
        body = (body or "").strip()

        if not body and not subject:
            raise ValueError("Email body or subject must not be empty.")

        # Ensure artifacts are available
        if not self.model or not self.vectorizer or not self.scaler:
            self.load_artifacts()
            if not self.model or not self.vectorizer:
                raise RuntimeError("ML model or vectorizer is not loaded. Train the model first.")

        # 1. Text Preprocessing & Static Analysis
        combined_text = f"Subject: {subject}\n\n{body}"
        cleaned_text = clean_text(combined_text)
        
        url_analysis = analyze_urls(body)
        structural_analysis = analyze_email_structure(sender, subject, body)
        detected_keywords = extract_suspicious_keywords(f"{subject} {cleaned_text}")

        # 2. Extract and format feature vector
        tfidf_features = self.vectorizer.transform([cleaned_text])
        num_features = extract_numerical_features(sender, subject, body)
        scaled_num_features = self.scaler.transform([num_features])
        
        combined_features = hstack([tfidf_features, csr_matrix(scaled_num_features)])

        # 3. Model Inference & Probabilities
        prediction_val = self.model.predict(combined_features)[0]
        probabilities = self.model.predict_proba(combined_features)[0]
        
        phishing_prob = float(probabilities[1])
        safe_prob = float(probabilities[0])

        is_phishing = bool(prediction_val == 1 or phishing_prob >= 0.50)
        prediction_label = "PHISHING" if is_phishing else "SAFE"
        confidence_percent = round((phishing_prob if is_phishing else safe_prob) * 100, 1)

        # 4. Multi-factor Risk Score Calculation (0 to 100)
        # Combines ML probability with specific threat indicators
        base_risk = phishing_prob * 60.0
        
        # URL threat additions
        url_threat_bonus = 0.0
        if url_analysis["urls_found"] > 0:
            if url_analysis["ip_based_urls"] > 0:
                url_threat_bonus += 20.0
            if url_analysis["shortened_urls"] > 0:
                url_threat_bonus += 15.0
            if url_analysis["has_at_symbol_urls"] > 0:
                url_threat_bonus += 15.0
            if url_analysis["suspicious_urls"] > 0:
                url_threat_bonus += 10.0
            if url_analysis["http_urls"] > 0 and url_analysis["https_urls"] == 0:
                url_threat_bonus += 8.0
        url_threat_bonus = min(25.0, url_threat_bonus)

        # Keyword density bonus
        kw_count = sum(k["count"] for k in detected_keywords)
        kw_bonus = min(15.0, kw_count * 2.5)

        # Structural & Header bonuses
        struct_bonus = 0.0
        if structural_analysis["subject_urgency"] or structural_analysis["subject_is_all_caps"]:
            struct_bonus += 5.0
        if structural_analysis["domain_suspicious"]:
            struct_bonus += 10.0
        struct_bonus = min(12.0, struct_bonus)

        # Composite score
        total_risk = base_risk + url_threat_bonus + kw_bonus + struct_bonus
        risk_score = int(np.clip(round(total_risk), 0, 100))

        # Categorize Risk Level according to specifications:
        # 0–30: LOW, 31–60: MEDIUM, 61–80: HIGH, 81–100: CRITICAL
        if risk_score <= 30:
            risk_level = "LOW"
        elif risk_score <= 60:
            risk_level = "MEDIUM"
        elif risk_score <= 80:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # 5. Dynamic SOC Explanation Generation
        explanation = []
        if is_phishing or risk_score >= 50:
            if structural_analysis["subject_urgency"] or any(k["keyword"] in ["urgent", "urgently", "action required", "immediately"] for k in detected_keywords):
                explanation.append("Contains urgent, coercive, or high-pressure language aimed at prompting hasty action.")
            if any(k["keyword"] in ["verify", "verification", "password", "login", "credential", "credentials", "account", "suspended", "restore"] for k in detected_keywords):
                explanation.append("Sollicits account credentials, password resets, or identity re-verification.")
            if url_analysis["urls_found"] > 0:
                if url_analysis["ip_based_urls"] > 0:
                    explanation.append("Contains raw IP address URL destination bypassing domain name resolution.")
                if url_analysis["shortened_urls"] > 0:
                    explanation.append("Utilizes URL redirection/shortener service designed to mask real destinations.")
                if url_analysis["suspicious_urls"] > 0:
                    explanation.append(f"Identified {url_analysis['suspicious_urls']} suspicious URL link(s) with anomalous structural characteristics.")
                if url_analysis["http_urls"] > 0 and url_analysis["https_urls"] == 0:
                    explanation.append("All embedded links use unencrypted HTTP protocol without SSL/TLS certificates.")
            if len(detected_keywords) >= 3:
                top_kw_str = ", ".join([f"'{k['keyword']}'" for k in detected_keywords[:5]])
                explanation.append(f"High concentration of known phishing triggers: {top_kw_str}.")
            if structural_analysis["domain_suspicious"]:
                explanation.append(f"Sender domain anomaly: {structural_analysis['domain_based_indicators']}.")
            explanation.append(f"Statistical text vector matches malicious phishing signatures with {confidence_percent}% confidence.")
        else:
            explanation.append("No credential harvesting or password solicitation detected.")
            if url_analysis["urls_found"] == 0:
                explanation.append("No embedded hyperlink threats or deceptive URLs found.")
            elif url_analysis["suspicious_urls"] == 0:
                explanation.append(f"All {url_analysis['urls_found']} detected URL link(s) adhere to standard secure HTTPS conventions.")
            explanation.append("Absence of coercive urgent language or fake suspension alerts.")
            explanation.append("Sender metadata and email formatting align with legitimate communication patterns.")
            explanation.append(f"Machine learning classifier evaluated message as legitimate safe content ({confidence_percent}% confidence).")

        return {
            "prediction": prediction_label,
            "confidence": confidence_percent,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "probabilities": {
                "phishing": round(phishing_prob * 100, 1),
                "safe": round(safe_prob * 100, 1)
            },
            "detected_keywords": detected_keywords,
            "url_analysis": url_analysis,
            "structural_analysis": structural_analysis,
            "explanation": explanation,
            "model_used": "Logistic Regression"
        }

# Global instance
ml_engine = MLEngine()

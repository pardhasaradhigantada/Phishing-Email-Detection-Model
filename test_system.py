import os
import io
import json
import unittest
from app import create_app
from models import db, User, EmailAnalysis, DatasetRecord
from feature_extraction import (
    clean_text, extract_suspicious_keywords,
    analyze_urls, analyze_email_structure
)
from ml_engine import ml_engine

class SystemTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def test_01_feature_extraction(self):
        """Test clean text, keyword extraction, and static URL analysis."""
        raw_html = "<p>URGENT: Click <a href='http://192.168.1.1/login'>here</a> to verify password!</p>"
        cleaned = clean_text(raw_html)
        self.assertNotIn("<p>", cleaned)
        self.assertIn("URGENT:", cleaned)

        # Keyword detection
        keywords = extract_suspicious_keywords(cleaned)
        kw_names = [k["keyword"] for k in keywords]
        self.assertIn("urgent", kw_names)
        self.assertIn("verify", kw_names)
        self.assertIn("password", kw_names)

        # URL static analysis
        url_analysis = analyze_urls("Please check http://192.168.1.1/login and https://trusted.com")
        self.assertEqual(url_analysis["urls_found"], 2)
        self.assertEqual(url_analysis["ip_based_urls"], 1)
        self.assertEqual(url_analysis["http_urls"], 1)
        self.assertEqual(url_analysis["https_urls"], 1)
        self.assertGreaterEqual(url_analysis["suspicious_urls"], 1)

    def test_02_ml_engine_inference(self):
        """Test ML inference on phishing vs safe emails."""
        # Phishing sample
        phish_res = ml_engine.predict_email(
            "security@paypal-verify.com",
            "Urgent: Account Suspended",
            "Click http://192.168.1.50/login immediately to verify your account password!"
        )
        self.assertEqual(phish_res["prediction"], "PHISHING")
        self.assertGreaterEqual(phish_res["confidence"], 50.0)
        self.assertGreaterEqual(phish_res["risk_score"], 60)
        self.assertIn(phish_res["risk_level"], ["HIGH", "CRITICAL"])
        self.assertGreater(len(phish_res["explanation"]), 0)

        # Safe sample
        safe_res = ml_engine.predict_email(
            "colleague@company.com",
            "Team Sprint Planning Sync",
            "Hi team, let's meet tomorrow at 10 AM to discuss Jira tickets: https://jira.atlassian.com/browse/PROJ-1"
        )
        self.assertEqual(safe_res["prediction"], "SAFE")
        self.assertLessEqual(safe_res["risk_score"], 35)
        self.assertIn(safe_res["risk_level"], ["LOW", "MEDIUM"])

    def test_03_authentication_and_dashboard(self):
        """Test login flow and protected dashboard."""
        # Unauthenticated access redirects to login
        res = cls = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

        # Authenticate with default admin
        login_res = self.client.post("/login", data={
            "username": "admin",
            "password": "Admin@123"
        }, follow_redirects=True)
        self.assertEqual(login_res.status_code, 200)
        self.assertIn(b"Security Operations Dashboard", login_res.data)

        # Access dashboard
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn(b"TOTAL EMAILS", dash_res.data)
        self.assertIn(b"PHISHING DETECTED", dash_res.data)

    def test_04_rest_api_analyze(self):
        """Test the REST API endpoint /api/analyze."""
        payload = {
            "sender": "alert@bank-security.net",
            "subject": "ACTION REQUIRED: Unauthorized Login Attempt",
            "body": "Your bank account has been locked. Verify immediately at http://198.51.100.22/bank/verify"
        }
        res = self.client.post("/api/analyze", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["prediction"], "PHISHING")
        self.assertIn("confidence", data["data"])
        self.assertIn("risk_score", data["data"])

    def test_05_rest_api_stats(self):
        """Test the dashboard stats API endpoint /api/stats."""
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("totals", data)
        self.assertIn("timeline", data)
        self.assertIn("ratio", data)
        self.assertIn("top_keywords", data)
        self.assertIn("url_indicators", data)

    def test_06_model_info_page(self):
        """Test the model evaluation metrics page."""
        res = self.client.get("/model")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Classifier Performance Metrics", res.data)
        self.assertIn(b"Confusion Matrix", res.data)
        self.assertIn(b"Classifier Comparison", res.data)

    def test_07_csv_validation_and_dataset(self):
        """Test CSV dataset validation logic."""
        # 1. Invalid CSV (missing label)
        bad_csv = io.BytesIO(b"text\nHello world")
        res = self.client.post("/dataset", data={
            "dataset_file": (bad_csv, "invalid.csv")
        }, follow_redirects=True)
        self.assertIn(b"Validation Failed", res.data)

        # 2. Valid CSV
        good_csv = io.BytesIO(b'text,label\n"Urgent reset password http://bad.com",phishing\n"Meeting at 2pm",safe\n')
        res2 = self.client.post("/dataset", data={
            "dataset_file": (good_csv, "valid.csv")
        }, follow_redirects=True)
        self.assertIn(b"Successfully validated and ingested", res2.data)

if __name__ == "__main__":
    unittest.main()

import unittest
import json
import io
from app import create_app
from models import db, User, EmailAnalysis, DatasetRecord

class FullVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def test_complete_workflow(self):
        print("\n[+] 1. Testing Authentication...")
        # Login GET
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"SENTINEL MAIL", res.data)
        self.assertIn(b"Auto-Fill", res.data)

        # Login POST with admin credentials
        login_post = self.client.post("/login", data={
            "username": "admin",
            "password": "Admin@123",
            "remember": "1"
        }, follow_redirects=True)
        self.assertEqual(login_post.status_code, 200)
        self.assertIn(b"Security Operations Dashboard", login_post.data)
        print("    -> Admin authentication verified successfully.")

        print("[+] 2. Testing Dashboard Statistics & Charts API...")
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn(b"TOTAL EMAILS", dash_res.data)
        self.assertIn(b"PHISHING DETECTED", dash_res.data)
        self.assertIn(b"MODEL ACCURACY", dash_res.data)

        stats_api = self.client.get("/api/stats")
        self.assertEqual(stats_api.status_code, 200)
        stats_json = stats_api.get_json()
        self.assertIn("timeline", stats_json)
        self.assertIn("ratio", stats_json)
        self.assertIn("top_keywords", stats_json)
        self.assertIn("url_indicators", stats_json)
        print(f"    -> Stats API verified: {stats_json['totals']['total']} total emails tracked.")

        print("[+] 3. Testing Email Analysis (Phishing Scenario)...")
        phish_payload = {
            "sender": "security-alert@paypal-account-verify.com",
            "subject": "Urgent: Verify Your Account - Access Suspended",
            "body": "Dear customer, your account has been suspended due to unauthorized login attempts. Click http://192.168.1.100/verify-login immediately to verify your password."
        }
        res_phish = self.client.post("/api/analyze", json=phish_payload)
        self.assertEqual(res_phish.status_code, 200)
        data_phish = res_phish.get_json()["data"]
        self.assertEqual(data_phish["prediction"], "PHISHING")
        self.assertGreaterEqual(data_phish["risk_score"], 60)
        self.assertIn("explanation", data_phish)
        self.assertGreater(len(data_phish["explanation"]), 0)
        print(f"    -> Phishing classified: {data_phish['prediction']}, Confidence: {data_phish['confidence']}%, Risk: {data_phish['risk_level']} ({data_phish['risk_score']}/100)")

        print("[+] 4. Testing Email Analysis (Safe Scenario)...")
        safe_payload = {
            "sender": "alex.rivera@acme-corp.com",
            "subject": "Sprint planning notes & roadmap update for Q3",
            "body": "Hi team, thanks everyone for joining today's roadmap review. Please check the Jira backlog: https://jira.atlassian.com/browse/PROJ-412"
        }
        res_safe = self.client.post("/api/analyze", json=safe_payload)
        self.assertEqual(res_safe.status_code, 200)
        data_safe = res_safe.get_json()["data"]
        self.assertEqual(data_safe["prediction"], "SAFE")
        self.assertLessEqual(data_safe["risk_score"], 35)
        print(f"    -> Safe email classified: {data_safe['prediction']}, Confidence: {data_safe['confidence']}%, Risk: {data_safe['risk_level']} ({data_safe['risk_score']}/100)")

        print("[+] 5. Testing History Logs & Telemetry Inspection...")
        hist_res = self.client.get("/history")
        self.assertEqual(hist_res.status_code, 200)
        self.assertIn(b"Historical Telemetry Logs", hist_res.data)

        # Inspect specific item
        item_id = data_phish["id"]
        detail_api = self.client.get(f"/api/history/{item_id}")
        self.assertEqual(detail_api.status_code, 200)
        detail_data = detail_api.get_json()
        self.assertEqual(detail_data["id"], item_id)
        self.assertEqual(detail_data["prediction"], "PHISHING")
        print(f"    -> Telemetry inspection API verified for record #{item_id}.")

        print("[+] 6. Testing Model Information & Comparison Page...")
        model_res = self.client.get("/model")
        self.assertEqual(model_res.status_code, 200)
        self.assertIn(b"Classifier Performance Metrics", model_res.data)
        self.assertIn(b"Confusion Matrix", model_res.data)
        self.assertIn(b"Random Forest", model_res.data)
        print("    -> Model info page verified with real metrics and classifier comparison.")

        print("[+] 7. Testing Dataset Manager & CSV Upload...")
        dataset_res = self.client.get("/dataset")
        self.assertEqual(dataset_res.status_code, 200)
        self.assertIn(b"Dataset Corpus Records", dataset_res.data)
        self.assertIn(b"Upload CSV Dataset", dataset_res.data)

        # Ingest CSV sample
        test_csv = io.BytesIO(b'text,label\n"Urgent login verification needed http://suspicious-site.cc/auth",phishing\n"Meeting summary from yesterday",safe\n')
        upload_res = self.client.post("/dataset", data={
            "dataset_file": (test_csv, "test_upload.csv")
        }, follow_redirects=True)
        self.assertEqual(upload_res.status_code, 200)
        self.assertIn(b"Successfully validated and ingested", upload_res.data)
        print("    -> Dataset management and CSV validation verified.")

        print("\n[SUCCESS] ALL APPLICATION WORKFLOWS AND FEATURES VERIFIED!")

if __name__ == "__main__":
    unittest.main()

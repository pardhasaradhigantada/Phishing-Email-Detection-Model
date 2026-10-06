import os
import json
import csv
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, send_file
)
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, EmailAnalysis, DatasetRecord
from ml_engine import ml_engine
from train_model import train_system_models
from feature_extraction import clean_text

# -------------------------------------------------------------
# Database Setup & Seeding Helpers
# -------------------------------------------------------------
def init_default_admin():
    admin = User.query.filter_by(username=Config.DEFAULT_ADMIN_USERNAME).first()
    if not admin:
        admin = User(
            username=Config.DEFAULT_ADMIN_USERNAME,
            email=Config.DEFAULT_ADMIN_EMAIL,
            role="admin"
        )
        admin.set_password(Config.DEFAULT_ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        print(f"[*] Created default admin user: {Config.DEFAULT_ADMIN_USERNAME} / {Config.DEFAULT_ADMIN_PASSWORD}")

def sync_initial_dataset_if_empty():
    if DatasetRecord.query.count() == 0 and os.path.exists(Config.DATASET_PATH):
        print("[*] Synchronizing initial dataset CSV into SQLite database...")
        try:
            with open(Config.DATASET_PATH, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                records = []
                for i, row in enumerate(reader):
                    rec = DatasetRecord(
                        sender=row.get("sender", ""),
                        subject=row.get("subject", ""),
                        body=row.get("body", row.get("text", "")),
                        label=row.get("label", "safe").lower().strip()
                    )
                    records.append(rec)
                    if len(records) >= 500:
                        db.session.bulk_save_objects(records)
                        db.session.commit()
                        records = []
                if records:
                    db.session.bulk_save_objects(records)
                    db.session.commit()
            print(f"[*] Ingested {DatasetRecord.query.count()} dataset records into SQLite.")
        except Exception as e:
            print(f"[!] Warning syncing dataset to DB: {e}")

def dump_db_to_csv():
    """Dumps SQLite DatasetRecords back to phishing_emails.csv for retraining."""
    records = DatasetRecord.query.all()
    with open(Config.DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sender", "subject", "body", "text", "label"])
        for r in records:
            combined_text = f"Subject: {r.subject or ''}\n\n{r.body}"
            writer.writerow([r.sender or "", r.subject or "", r.body, combined_text, r.label])

def validate_and_parse_csv(file_path):
    """Strict CSV schema and row validator."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        try:
            reader = csv.DictReader(f)
        except Exception:
            return False, "File is not a valid comma-separated CSV format.", []
        
        headers = [h.strip().lower() for h in (reader.fieldnames or [])]
        if "label" not in headers:
            return False, "Missing mandatory 'label' column in CSV header.", []

        has_text = "text" in headers or "body" in headers
        if not has_text:
            return False, "CSV must contain either a 'text' or 'body' column.", []

        validated_rows = []
        for row_idx, row in enumerate(reader, start=2):
            lbl = (row.get("label") or "").strip().lower()
            if lbl not in ["phishing", "safe"]:
                return False, f"Row {row_idx}: Invalid label '{lbl}'. Must be either 'phishing' or 'safe'.", []
            
            txt = (row.get("text") or row.get("body") or "").strip()
            if not txt:
                return False, f"Row {row_idx}: Text content is empty.", []
            
            validated_rows.append({
                "sender": row.get("sender", "").strip(),
                "subject": row.get("subject", "").strip(),
                "body": row.get("body", txt).strip(),
                "text": txt,
                "label": lbl
            })

        if not validated_rows:
            return False, "Uploaded CSV contains no valid data rows.", []

        return True, "Valid", validated_rows

def seed_initial_history_if_empty():
    """Seeds initial realistic analyses across past 7 days for rich dashboard charts."""
    if EmailAnalysis.query.count() == 0:
        print("[*] Seeding realistic initial historical analyses for dashboard visualization...")
        seed_samples = [
            {
                "sender": "security-alert@paypal-account-verify.com",
                "subject": "URGENT: Your PayPal account has been limited",
                "body": "Dear customer, your account has been limited due to suspicious access. Click http://192.168.1.100/verify immediately to confirm your password.",
                "days_ago": 6
            },
            {
                "sender": "support@chase.com",
                "subject": "Monthly Statement Available",
                "body": "Your electronic monthly statement is available for viewing. Please visit https://www.chase.com through your browser to view your document.",
                "days_ago": 6
            },
            {
                "sender": "it-desk@corporate-sso-gateway.info",
                "subject": "ACTION REQUIRED: Office 365 Password Expiration Notice",
                "body": "Attention, your corporate password will expire in 2 hours. Keep your password unchanged: http://bit.ly/sso-update-token. Do not ignore.",
                "days_ago": 5
            },
            {
                "sender": "notifications@github.com",
                "subject": "[GitHub] Automated security scan completed: 0 alerts",
                "body": "Code scanning completed on repository core-api. Visit https://github.com/org/core-api/security/code-scanning to view the full report.",
                "days_ago": 5
            },
            {
                "sender": "claims@irs-tax-refund-portal.org",
                "subject": "Federal Tax Refund of $2,450.00 Ready for Disbursement",
                "body": "You have a pending tax refund. Click http://refund-claim-irs.org/ssn/verify to enter your SSN and banking credentials immediately.",
                "days_ago": 4
            },
            {
                "sender": "alex.chen@innovate.co",
                "subject": "Architecture design review sync agenda",
                "body": "Hi team, looking forward to our architectural discussion tomorrow. Slides are linked here: https://docs.google.com/presentation/d/123",
                "days_ago": 4
            },
            {
                "sender": "service@delivery-fee-hold.net",
                "subject": "Delivery Alert: Package #918290 held at customs",
                "body": "Your package is on hold due to missing address info. Pay $2.95 customs fee at http://track-package-update.com/pay to release your shipment.",
                "days_ago": 3
            },
            {
                "sender": "billing@stripe.com",
                "subject": "Your Stripe receipt for invoice #INV-2041",
                "body": "Thank you for your payment of $120.00 USD. You can review your transaction history at https://dashboard.stripe.com/receipts",
                "days_ago": 3
            },
            {
                "sender": "hr-compliance@benefits-portal-login.info",
                "subject": "Urgent Action: Update Direct Deposit Information",
                "body": "Please confirm your banking details on the employee portal http://104.244.42.1/hr/direct-deposit to prevent salary delay.",
                "days_ago": 2
            },
            {
                "sender": "no-reply@zoom.us",
                "subject": "Meeting invitation: Q3 Security Strategy Review",
                "body": "You have been invited to a Zoom meeting. Join URL: https://zoom.us/j/912839129. Passcode: 481920.",
                "days_ago": 2
            },
            {
                "sender": "billing-notice@geek-squad-support.com",
                "subject": "Geek Squad Auto-Renewal #84918 - $499.00 Charged",
                "body": "Your subscription has been renewed for $499.00. If you did not make this purchase, call immediately or dispute here: http://refund-dispute-portal.com/login",
                "days_ago": 1
            },
            {
                "sender": "editor@techdigest.com",
                "subject": "Weekly Tech Digest: AI Cybersecurity Defense Trends",
                "body": "Check out our latest publication covering automated phishing detection models: https://towardsdatascience.com/phishing-nlp-2026",
                "days_ago": 1
            },
            {
                "sender": "admin@netflix-billing-update.org",
                "subject": "Notice: Your Netflix membership is on hold",
                "body": "We were unable to process your monthly payment. Click http://netflix-account-restart.com to update your payment information.",
                "days_ago": 0
            },
            {
                "sender": "david@acme-corp.com",
                "subject": "Sprint planning notes & roadmap update for Q3",
                "body": "Hi team, thanks everyone for joining today's roadmap review. Please check the Jira backlog: https://jira.atlassian.com/browse/PROJ-412",
                "days_ago": 0
            }
        ]

        for s in seed_samples:
            res = ml_engine.predict_email(s["sender"], s["subject"], s["body"])
            record = EmailAnalysis(
                sender=s["sender"],
                subject=s["subject"],
                body=s["body"],
                prediction=res["prediction"],
                confidence=res["confidence"],
                risk_score=res["risk_score"],
                risk_level=res["risk_level"],
                detected_keywords_json=json.dumps(res["detected_keywords"]),
                url_analysis_json=json.dumps(res["url_analysis"]),
                structural_analysis_json=json.dumps(res["structural_analysis"]),
                explanation_json=json.dumps(res["explanation"]),
                model_used=res["model_used"],
                created_at=datetime.now() - timedelta(days=s["days_ago"])
            )
            db.session.add(record)
        db.session.commit()
        print("[*] Historical analyses successfully seeded into database.")


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize database
    db.init_app(app)
    
    # Ensure directories exist
    os.makedirs(Config.DATASET_DIR, exist_ok=True)
    os.makedirs(Config.MODELS_DIR, exist_ok=True)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    with app.app_context():
        db.create_all()
        init_default_admin()
        sync_initial_dataset_if_empty()
        seed_initial_history_if_empty()

    # -------------------------------------------------------------
    # Authentication Decorator & Helpers
    # -------------------------------------------------------------
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please authenticate to access the Security Operations Center.", "warning")
                return redirect(url_for("login", next=request.path))
            return f(*args, **kwargs)
        return decorated_function

    @app.context_processor
    def inject_user():
        current_user = None
        if "user_id" in session:
            current_user = db.session.get(User, session["user_id"])
        return dict(current_user=current_user)

    # -------------------------------------------------------------
    # Auth Routes
    # -------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
            
        if request.method == "POST":
            username_or_email = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            remember = bool(request.form.get("remember"))

            user = User.query.filter(
                (User.username == username_or_email) | (User.email == username_or_email)
            ).first()

            if user and user.check_password(password):
                session.permanent = remember
                session["user_id"] = user.id
                session["username"] = user.username
                session["role"] = user.role
                flash(f"Welcome back, Analyst {user.username}. Security session initialized.", "success")
                next_page = request.args.get("next")
                return redirect(next_page if next_page else url_for("dashboard"))
            else:
                flash("Invalid credentials. Please verify your username/email and password.", "danger")

        return render_template(
            "login.html",
            default_admin_email=Config.DEFAULT_ADMIN_EMAIL,
            default_admin_password=Config.DEFAULT_ADMIN_PASSWORD
        )

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Security session terminated successfully.", "info")
        return redirect(url_for("login"))

    # -------------------------------------------------------------
    # Main Dashboard Route
    # -------------------------------------------------------------
    @app.route("/")
    @app.route("/dashboard")
    @login_required
    def dashboard():
        # Get live DB counts
        total_emails = EmailAnalysis.query.count()
        phishing_count = EmailAnalysis.query.filter_by(prediction="PHISHING").count()
        safe_count = EmailAnalysis.query.filter_by(prediction="SAFE").count()
        
        detection_rate = round((phishing_count / total_emails * 100), 1) if total_emails > 0 else 0.0

        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        analyzed_today = EmailAnalysis.query.filter(EmailAnalysis.created_at >= today_start).count()

        # Model accuracy from real metrics
        model_acc = 95.0
        if ml_engine.metrics and "primary_model" in ml_engine.metrics:
            model_acc = ml_engine.metrics["primary_model"].get("accuracy", 95.0)

        recent_analyses = EmailAnalysis.query.order_by(EmailAnalysis.created_at.desc()).limit(8).all()

        return render_template(
            "dashboard.html",
            total_emails=total_emails,
            phishing_count=phishing_count,
            safe_count=safe_count,
            detection_rate=detection_rate,
            analyzed_today=analyzed_today,
            model_accuracy=model_acc,
            recent_analyses=recent_analyses
        )

    # -------------------------------------------------------------
    # Email Analysis Page
    # -------------------------------------------------------------
    @app.route("/analyze", methods=["GET", "POST"])
    @login_required
    def analyze():
        result = None
        form_data = {
            "sender": "",
            "subject": "",
            "body": ""
        }

        if request.method == "POST":
            form_data["sender"] = request.form.get("sender", "").strip()
            form_data["subject"] = request.form.get("subject", "").strip()
            form_data["body"] = request.form.get("body", "").strip()

            if not form_data["body"] and not form_data["subject"]:
                flash("Please provide email body text or subject for inspection.", "warning")
            else:
                try:
                    result = ml_engine.predict_email(
                        form_data["sender"],
                        form_data["subject"],
                        form_data["body"]
                    )
                    # Persist analysis
                    analysis_record = EmailAnalysis(
                        sender=form_data["sender"],
                        subject=form_data["subject"],
                        body=form_data["body"],
                        prediction=result["prediction"],
                        confidence=result["confidence"],
                        risk_score=result["risk_score"],
                        risk_level=result["risk_level"],
                        detected_keywords_json=json.dumps(result["detected_keywords"]),
                        url_analysis_json=json.dumps(result["url_analysis"]),
                        structural_analysis_json=json.dumps(result["structural_analysis"]),
                        explanation_json=json.dumps(result["explanation"]),
                        model_used=result["model_used"],
                        user_id=session.get("user_id")
                    )
                    db.session.add(analysis_record)
                    db.session.commit()
                    result["id"] = analysis_record.id
                except Exception as e:
                    flash(f"Analysis error: {str(e)}", "danger")

        return render_template("analyze.html", result=result, form_data=form_data)

    # -------------------------------------------------------------
    # History Log Page
    # -------------------------------------------------------------
    @app.route("/history")
    @login_required
    def history():
        filter_status = request.args.get("status", "ALL")
        filter_risk = request.args.get("risk", "ALL")
        query_text = request.args.get("q", "").strip()
        page = request.args.get("page", 1, type=int)
        per_page = 15

        query = EmailAnalysis.query

        if filter_status in ["PHISHING", "SAFE"]:
            query = query.filter_by(prediction=filter_status)
        if filter_risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            query = query.filter_by(risk_level=filter_risk)
        if query_text:
            query = query.filter(
                (EmailAnalysis.subject.ilike(f"%{query_text}%")) |
                (EmailAnalysis.sender.ilike(f"%{query_text}%")) |
                (EmailAnalysis.body.ilike(f"%{query_text}%"))
            )

        pagination = query.order_by(EmailAnalysis.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return render_template(
            "history.html",
            pagination=pagination,
            filter_status=filter_status,
            filter_risk=filter_risk,
            query_text=query_text
        )

    # -------------------------------------------------------------
    # Model Information & Evaluation Page
    # -------------------------------------------------------------
    @app.route("/model")
    @login_required
    def model_info():
        metrics = ml_engine.metrics or {}
        feature_config = ml_engine.feature_config or {}
        return render_template("model_info.html", metrics=metrics, config=feature_config)

    # -------------------------------------------------------------
    # Dataset Management Page
    # -------------------------------------------------------------
    @app.route("/dataset", methods=["GET", "POST"])
    @login_required
    def dataset():
        if request.method == "POST":
            # Handle dataset CSV upload
            if "dataset_file" not in request.files:
                flash("No file was uploaded.", "warning")
                return redirect(url_for("dataset"))
                
            file = request.files["dataset_file"]
            if file.filename == "":
                flash("No file was selected.", "warning")
                return redirect(url_for("dataset"))
                
            if not file.filename.endswith(".csv"):
                flash("Validation Error: Only CSV files (.csv) are accepted.", "danger")
                return redirect(url_for("dataset"))

            try:
                # Save uploaded file temporarily for validation
                filename = secure_filename(file.filename)
                upload_path = os.path.join(Config.UPLOAD_FOLDER, filename)
                file.save(upload_path)

                # Validate CSV structure
                valid, msg, validated_rows = validate_and_parse_csv(upload_path)
                if not valid:
                    flash(f"CSV Validation Failed: {msg}", "danger")
                    if os.path.exists(upload_path):
                        os.remove(upload_path)
                    return redirect(url_for("dataset"))

                # Ingest validated records into SQLite & update CSV
                new_records_count = 0
                for r in validated_rows:
                    rec = DatasetRecord(
                        sender=r.get("sender", ""),
                        subject=r.get("subject", ""),
                        body=r.get("body", r.get("text", "")),
                        label=r["label"].lower()
                    )
                    db.session.add(rec)
                    new_records_count += 1
                db.session.commit()

                # Overwrite or append to active training dataset CSV
                dump_db_to_csv()

                flash(f"Successfully validated and ingested {new_records_count} records into dataset!", "success")
                return redirect(url_for("dataset"))
            except Exception as e:
                flash(f"Error processing CSV: {str(e)}", "danger")
                return redirect(url_for("dataset"))

        # GET request: render dataset stats and samples
        page = request.args.get("page", 1, type=int)
        query_filter = request.args.get("label", "ALL")
        per_page = 15

        db_query = DatasetRecord.query
        if query_filter in ["phishing", "safe"]:
            db_query = db_query.filter_by(label=query_filter)

        pagination = db_query.order_by(DatasetRecord.id.asc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        total_records = DatasetRecord.query.count()
        phishing_count = DatasetRecord.query.filter_by(label="phishing").count()
        safe_count = DatasetRecord.query.filter_by(label="safe").count()
        balance_ratio = f"{phishing_count}:{safe_count}" if safe_count > 0 else "N/A"

        return render_template(
            "dataset.html",
            pagination=pagination,
            total_records=total_records,
            phishing_count=phishing_count,
            safe_count=safe_count,
            balance_ratio=balance_ratio,
            query_filter=query_filter
        )

    # -------------------------------------------------------------
    # REST APIs
    # -------------------------------------------------------------
    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        """Public or authenticated REST API for scanning emails."""
        try:
            data = request.get_json(force=True, silent=True) or request.form
            sender = data.get("sender", "")
            subject = data.get("subject", "")
            body = data.get("body", "")

            if not body and not subject:
                return jsonify({"error": "Missing email body or subject"}), 400

            result = ml_engine.predict_email(sender, subject, body)

            # Persist to DB
            analysis_record = EmailAnalysis(
                sender=sender,
                subject=subject,
                body=body,
                prediction=result["prediction"],
                confidence=result["confidence"],
                risk_score=result["risk_score"],
                risk_level=result["risk_level"],
                detected_keywords_json=json.dumps(result["detected_keywords"]),
                url_analysis_json=json.dumps(result["url_analysis"]),
                structural_analysis_json=json.dumps(result["structural_analysis"]),
                explanation_json=json.dumps(result["explanation"]),
                model_used=result["model_used"],
                user_id=session.get("user_id")
            )
            db.session.add(analysis_record)
            db.session.commit()
            result["id"] = analysis_record.id

            return jsonify({"status": "success", "data": result}), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/stats", methods=["GET"])
    @login_required
    def api_stats():
        """Returns dynamic data for dashboard statistics and Chart.js charts."""
        # 1. Status Counts
        total = EmailAnalysis.query.count()
        phishing = EmailAnalysis.query.filter_by(prediction="PHISHING").count()
        safe = EmailAnalysis.query.filter_by(prediction="SAFE").count()
        
        # 2. Daily trend over past 7 days
        days = []
        trend_phishing = []
        trend_safe = []
        now = datetime.now()
        for i in range(6, -1, -1):
            day_dt = now - timedelta(days=i)
            day_str = day_dt.strftime("%b %d")
            start = day_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1)
            p_cnt = EmailAnalysis.query.filter(
                EmailAnalysis.prediction == "PHISHING",
                EmailAnalysis.created_at >= start,
                EmailAnalysis.created_at < end
            ).count()
            s_cnt = EmailAnalysis.query.filter(
                EmailAnalysis.prediction == "SAFE",
                EmailAnalysis.created_at >= start,
                EmailAnalysis.created_at < end
            ).count()
            days.append(day_str)
            trend_phishing.append(p_cnt)
            trend_safe.append(s_cnt)

        # 3. Aggregated Top Keywords
        keyword_counts = {}
        all_analyses = EmailAnalysis.query.order_by(EmailAnalysis.id.desc()).limit(150).all()
        for a in all_analyses:
            for kw in a.detected_keywords:
                name = kw.get("keyword", "")
                keyword_counts[name] = keyword_counts.get(name, 0) + kw.get("count", 1)

        sorted_kw = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        kw_labels = [k[0] for k in sorted_kw] if sorted_kw else ["urgent", "verify", "password", "account", "click"]
        kw_values = [k[1] for k in sorted_kw] if sorted_kw else [12, 10, 8, 7, 5]

        # 4. URL Threat Indicators count
        url_threat_stats = {
            "IP-based Host": 0,
            "Shortened URLs": 0,
            "HTTP Unencrypted": 0,
            "Excessive Hyphens": 0,
            "Anomalous Ports": 0
        }
        for a in all_analyses:
            u_info = a.url_analysis
            if u_info.get("ip_based_urls", 0) > 0:
                url_threat_stats["IP-based Host"] += 1
            if u_info.get("shortened_urls", 0) > 0:
                url_threat_stats["Shortened URLs"] += 1
            if u_info.get("http_urls", 0) > 0:
                url_threat_stats["HTTP Unencrypted"] += 1
            for d in u_info.get("details", []):
                if d.get("excessive_hyphens"):
                    url_threat_stats["Excessive Hyphens"] += 1
                if d.get("unusual_port"):
                    url_threat_stats["Anomalous Ports"] += 1

        return jsonify({
            "totals": {
                "total": total,
                "phishing": phishing,
                "safe": safe,
                "detection_rate": round(phishing / total * 100, 1) if total > 0 else 0
            },
            "timeline": {
                "labels": days,
                "phishing": trend_phishing,
                "safe": trend_safe
            },
            "ratio": {
                "labels": ["Phishing", "Safe"],
                "data": [phishing, safe]
            },
            "top_keywords": {
                "labels": kw_labels,
                "data": kw_values
            },
            "url_indicators": {
                "labels": list(url_threat_stats.keys()),
                "data": list(url_threat_stats.values())
            }
        })

    @app.route("/api/history/<int:analysis_id>", methods=["GET"])
    @login_required
    def api_get_analysis_detail(analysis_id):
        record = db.session.get(EmailAnalysis, analysis_id)
        if not record:
            return jsonify({"error": "Record not found"}), 404
        return jsonify(record.to_dict())

    @app.route("/api/retrain", methods=["POST"])
    @login_required
    def api_retrain():
        try:
            metrics = train_system_models()
            ml_engine.load_artifacts()
            return jsonify({
                "status": "success",
                "message": "Model retraining completed successfully.",
                "metrics": metrics
            }), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/export-history", methods=["GET"])
    @login_required
    def export_history():
        """Exports analysis history as a downloadable CSV."""
        export_path = os.path.join(Config.UPLOAD_FOLDER, "analysis_report_export.csv")
        analyses = EmailAnalysis.query.order_by(EmailAnalysis.created_at.desc()).all()
        with open(export_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Timestamp", "Sender", "Subject", "Prediction", "Confidence %", "Risk Score", "Risk Level", "Model"])
            for a in analyses:
                writer.writerow([
                    a.id,
                    a.created_at.strftime("%Y-%m-%d %H:%M:%S") if a.created_at else "",
                    a.sender or "",
                    a.subject or "",
                    a.prediction,
                    a.confidence,
                    a.risk_score,
                    a.risk_level,
                    a.model_used
                ])
        return send_file(export_path, as_attachment=True, download_name="phishing_soc_analyses.csv")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)

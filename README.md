# SentinelMail // Phishing Email Detection & Analysis System

A production-style **Cybersecurity SOC (Security Operations Center)** web application that analyzes incoming email payloads and predicts whether they are **SAFE** or **PHISHING** using **Scikit-learn Machine Learning, Natural Language Processing (TF-IDF), Static URL Triage, and Heuristic Risk Scoring**.

Built with **Python, Flask, Scikit-learn, SQLite, SQLAlchemy, HTML5, Vanilla CSS3, JavaScript, and Chart.js**.

---

## 🛡️ Key Features

### 1. Dual-Engine Threat Detection
- **Textual Feature Extraction (NLP)**:
  - Cleaned text normalization (HTML stripping, entity unescaping, character density).
  - TF-IDF Vectorization with unigrams & bigrams and sublinear term frequency scaling.
  - Structural signals: Word counts, sentence counts, average word length, uppercase shouting ratio, punctuation frequencies (`!`, `$`).
- **Configurable Suspicious Keywords Detection**:
  - Scans for 40+ phishing trigger keywords (`urgent`, `verify`, `password`, `account`, `suspended`, `wire transfer`, `invoice`, `winner`, etc.).
  - Evaluates keyword concentration and frequency without false-positive single-word triggers.
- **Static URL Analysis (Zero Outbound Execution)**:
  - Total URLs detected, HTTP vs HTTPS protocol flags.
  - IP-based host detection (e.g., `http://192.168.1.1/login`).
  - URL shorteners detection (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, etc.).
  - Character anomalies (`@` symbol redirection, excessive hyphens, hex escapes, punycode/IDN `xn--`).
  - Anomalous port indicators (e.g., `:8080`, `:8888`).
  - Path/query credential keywords (`login`, `verify`, `secure`, `account`).
- **Sender & Structural Header Analysis**:
  - Sender display name and domain extraction.
  - Domain spoofing & free webmail provider mismatch flags.
  - Subject urgency evaluation.

### 2. Multi-Factor Risk Score (0–100) vs ML Confidence
- **ML Confidence Score**: Statistical probability output from the trained ML classifier.
- **Threat Risk Score**: Composite score (0–100) combining ML probability with URL threats, keyword density, and domain anomalies.
  - `0–30`: **LOW**
  - `31–60`: **MEDIUM**
  - `61–80`: **HIGH**
  - `81–100`: **CRITICAL**

### 3. Dynamic SOC Explanation System
- Automated, human-readable breakdown explaining *why* an email was flagged (or why it appears safe) with bullet points and forensic indicators.

### 4. Interactive SOC Operations Dashboard
- 6 Statistics Cards: Total Emails, Phishing Detections, Safe Emails, Detection Rate, Real Model Accuracy, Analyzed Today.
- 4 Live Chart.js Charts:
  1. Phishing Detection Trend (7-day area/line chart).
  2. Safe vs Phishing Ratio (Doughnut chart).
  3. Top Suspicious Keywords Detected (Horizontal bar chart).
  4. Most Common URL Indicators (Bar chart).
- Recent Telemetry Detections table with 1-click **Inspect** modal.

### 5. Email Analysis Studio
- Form inputs for Sender, Subject, and large multiline Email Body editor with live character count.
- **7 Quick-Test Scenario Templates**:
  - ⚠ PayPal Account Suspension & Credential Verification (Phishing)
  - ⚠ Office 365 Password Expiration Alert (Phishing)
  - ⚠ FedEx Package Customs Fee Scam (Phishing)
  - ⚠ Overdue Wire Invoice Dispute (Phishing)
  - ✓ Sprint Planning Meeting & Jira Roadmap (Safe)
  - ✓ Monthly SaaS Subscription Receipt (Safe)
  - ✓ Zoom Calendar Invitation (Safe)
- Instant AJAX analysis with large visual result banner, dual meters, keyword chips, URL forensic table, and header analysis.

### 6. Historical Telemetry Log & Forensics
- Filter by Verdict (`PHISHING`, `SAFE`) and Risk Level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- Text search across sender, subject, and body snippet.
- Full forensic inspection modal for any past analysis.
- **Export to CSV** functionality (`/api/export-history`).

### 7. Model Evaluation & Comparison
- Evaluated on 20% unseen test split with stratified sampling.
- True performance metrics: Accuracy, Precision, Recall, F1-Score, ROC-AUC.
- Interactive **Confusion Matrix** (True Positive, True Negative, False Positive, False Negative).
- Side-by-side **Model Comparison** (Logistic Regression vs Random Forest).
- 1-Click **Retrain Model** pipeline with progress feedback.

### 8. Dataset Manager & CSV Validator
- Corpus balance telemetry (Total records, Phishing count, Safe count, balance ratio).
- Paginated table of training samples.
- Secure **CSV Upload Form** with strict schema validation (`text,label` or `sender,subject,body,label`).

### 9. Analyst Authentication
- Secure authentication system with password hashing (`generate_password_hash` via Werkzeug).
- Session management with remember me support.
- Pre-configured default administrator credentials with 1-click **Auto-Fill** button.

---

## 🚀 Quick Start & Installation

### 1. Requirements
- Python 3.10+ (Tested on Python 3.13)
- Modern web browser (Chrome, Edge, Firefox, Safari)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate Seed Dataset & Train Models (Already Pre-Trained)
```bash
python dataset/seed_dataset.py
python train_model.py
```

### 4. Run the Application
```bash
python app.py
```
Open your web browser and navigate to:
**`http://127.0.0.1:5000`**

---

## 🔑 Default Administrator Credentials

| Username | Email | Password | Role |
| :--- | :--- | :--- | :--- |
| `admin` | `admin@security.local` | `Admin@123` | Administrator / Lead Analyst |

*(A 1-click **Auto-Fill** button is available directly on the login screen for instant testing).*

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/analyze` | `POST` | Analyzes an email payload (JSON: `sender`, `subject`, `body`). Returns prediction, confidence, risk score, keywords, URL stats, and explanations. |
| `/api/stats` | `GET` | Returns real-time counts, 7-day timeline trends, threat ratio, top keywords, and URL indicators for Chart.js. |
| `/api/history/<id>` | `GET` | Returns complete forensic telemetry record for a specific incident. |
| `/api/retrain` | `POST` | Triggers background model retraining pipeline and reloads artifacts. |
| `/api/export-history` | `GET` | Exports complete database of past scans as a downloadable CSV. |

---

## 🧪 Automated Testing
Run the complete unit and integration test suite:
```bash
python test_system.py
python verify_all_features.py
```
Both test suites evaluate feature extraction, ML inference, user authentication, dashboard metrics, REST APIs, and dataset CSV upload validation.

---

## 📁 Project Structure

```
Phishing Email Detection Model/
├── app.py                      # Flask application factory, routes, APIs, auth & database seeding
├── config.py                   # Central configuration & file paths
├── models.py                   # SQLAlchemy models (User, EmailAnalysis, DatasetRecord)
├── feature_extraction.py       # Static NLP, URL heuristics, and structural feature extractors
├── ml_engine.py                # Runtime ML inference, probability calculation, and risk scoring
├── train_model.py              # ML training & evaluation script (Logistic Regression & Random Forest)
├── test_system.py              # Unit & integration test suite
├── verify_all_features.py      # End-to-end full workflow verification script
│
├── dataset/
│   ├── phishing_emails.csv     # 2,500+ curated training emails
│   └── seed_dataset.py         # Realistic dataset generator script
│
├── saved_models/
│   ├── email_classifier.joblib # Trained Logistic Regression model
│   ├── rf_classifier.joblib    # Trained Random Forest model
│   ├── vectorizer.joblib       # Fitted TF-IDF vectorizer
│   ├── scaler.joblib           # Fitted StandardScaler
│   ├── feature_config.json     # Feature names & configuration metadata
│   └── model_metrics.json      # Accurate evaluation metrics on test split
│
├── static/
│   ├── css/
│   │   └── style.css           # Custom SOC dark theme styling
│   └── js/
│       ├── dashboard.js        # Chart.js charts & live stats
│       ├── analyzer.js         # Scenario loader & AJAX analyzer
│       ├── history.js          # Forensic inspection modal logic
│       └── model.js            # Model comparison chart & retrain trigger
│
├── templates/
│   ├── base.html               # Master layout with sidebar & top navbar
│   ├── login.html              # Analyst authentication screen
│   ├── dashboard.html          # Main SOC operations overview & charts
│   ├── analyze.html            # Dedicated email analysis studio
│   ├── _analysis_result_card.html # Result card component
│   ├── history.html            # Telemetry audit trail & filterable logs
│   ├── model_info.html         # Performance metrics, confusion matrix & model comparison
│   └── dataset.html            # Dataset manager & CSV uploader
│
├── requirements.txt            # Package dependencies
└── README.md                   # System documentation
```

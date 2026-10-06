import os
import json
import joblib
import pandas as pd
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)

from config import Config
from feature_extraction import (
    clean_text, extract_numerical_features, FEATURE_NAMES
)

def train_system_models(dataset_path: str = None):
    """
    Complete end-to-end model training pipeline:
    1. Loads and validates dataset
    2. Cleans text & extracts engineered features
    3. Splits with stratification and fixed random seed
    4. Trains Logistic Regression & Random Forest
    5. Evaluates real metrics on unseen test split
    6. Persists artifacts (models, vectorizer, scaler, metrics, feature config)
    """
    dataset_file = dataset_path or Config.DATASET_PATH
    print(f"[*] Loading dataset from: {dataset_file}")
    
    if not os.path.exists(dataset_file):
        raise FileNotFoundError(f"Dataset file not found at {dataset_file}")
        
    df = pd.read_csv(dataset_file)
    
    # Dataset validation
    if "label" not in df.columns:
        raise ValueError("Dataset missing required 'label' column.")
    
    # Standardize label values to lowercase strings
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    valid_labels = {"phishing", "safe"}
    invalid_rows = df[~df["label"].isin(valid_labels)]
    if len(invalid_rows) > 0:
        print(f"[!] Warning: Dropping {len(invalid_rows)} rows with non-standard labels.")
        df = df[df["label"].isin(valid_labels)]
        
    # Support multiple formats: text column or subject + body
    if "text" not in df.columns:
        subject_col = df["subject"].fillna("") if "subject" in df.columns else ""
        body_col = df["body"].fillna("") if "body" in df.columns else ""
        df["text"] = "Subject: " + subject_col + "\n\n" + body_col
    else:
        df["text"] = df["text"].fillna("")
        
    sender_col = df["sender"].fillna("") if "sender" in df.columns else pd.Series([""] * len(df))
    subject_col = df["subject"].fillna("") if "subject" in df.columns else pd.Series([""] * len(df))
    body_col = df["body"].fillna("") if "body" in df.columns else df["text"]

    print(f"[*] Total valid dataset samples: {len(df)}")
    label_counts = df["label"].value_counts().to_dict()
    print(f"[*] Distribution: {label_counts}")

    # Map labels: phishing -> 1, safe -> 0
    y = df["label"].map({"phishing": 1, "safe": 0}).values

    # Step 1: Preprocess text
    print("[*] Cleaning text and extracting engineered features...")
    cleaned_texts = [clean_text(t) for t in df["text"]]

    # Step 2: Extract numerical features for each sample
    num_features_list = []
    for s, subj, b in zip(sender_col, subject_col, body_col):
        feats = extract_numerical_features(str(s), str(subj), str(b))
        num_features_list.append(feats)
    X_num = np.array(num_features_list)

    # Step 3: Stratified Train/Test Split (80% train, 20% test)
    indices = np.arange(len(df))
    train_idx, test_idx, y_train, y_test = train_test_split(
        indices, y, test_size=0.2, stratify=y, random_state=42
    )

    train_texts = [cleaned_texts[i] for i in train_idx]
    test_texts = [cleaned_texts[i] for i in test_idx]
    X_num_train = X_num[train_idx]
    X_num_test = X_num[test_idx]

    # Step 4: Fit TF-IDF Vectorizer on train text only
    print("[*] Fitting TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words="english"
    )
    X_tfidf_train = vectorizer.fit_transform(train_texts)
    X_tfidf_test = vectorizer.transform(test_texts)

    # Step 5: Scale numerical features
    scaler = StandardScaler()
    X_num_train_scaled = scaler.fit_transform(X_num_train)
    X_num_test_scaled = scaler.transform(X_num_test)

    # Combine TF-IDF and scaled numerical features into sparse matrix
    X_train_combined = hstack([X_tfidf_train, csr_matrix(X_num_train_scaled)])
    X_test_combined = hstack([X_tfidf_test, csr_matrix(X_num_test_scaled)])

    # Step 6: Train Primary Model (Logistic Regression)
    print("[*] Training Primary Model: Logistic Regression...")
    lr_model = LogisticRegression(C=2.5, max_iter=1000, random_state=42)
    lr_model.fit(X_train_combined, y_train)

    lr_pred = lr_model.predict(X_test_combined)
    lr_proba = lr_model.predict_proba(X_test_combined)[:, 1]

    # Calculate real evaluation metrics for Logistic Regression
    lr_acc = float(accuracy_score(y_test, lr_pred))
    lr_prec = float(precision_score(y_test, lr_pred))
    lr_rec = float(recall_score(y_test, lr_pred))
    lr_f1 = float(f1_score(y_test, lr_pred))
    lr_auc = float(roc_auc_score(y_test, lr_proba))
    lr_cm = confusion_matrix(y_test, lr_pred).tolist()

    print("\n================== LOGISTIC REGRESSION RESULTS ==================")
    print(f"Accuracy:  {lr_acc * 100:.2f}%")
    print(f"Precision: {lr_prec * 100:.2f}%")
    print(f"Recall:    {lr_rec * 100:.2f}%")
    print(f"F1-Score:  {lr_f1 * 100:.2f}%")
    print(f"ROC-AUC:   {lr_auc * 100:.2f}%")
    print("Confusion Matrix (TN, FP / FN, TP):", lr_cm)

    # Step 7: Train Comparator Model (Random Forest)
    print("\n[*] Training Comparator Model: Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=120, max_depth=25, random_state=42, n_jobs=-1)
    rf_model.fit(X_train_combined, y_train)

    rf_pred = rf_model.predict(X_test_combined)
    rf_proba = rf_model.predict_proba(X_test_combined)[:, 1]

    rf_acc = float(accuracy_score(y_test, rf_pred))
    rf_prec = float(precision_score(y_test, rf_pred))
    rf_rec = float(recall_score(y_test, rf_pred))
    rf_f1 = float(f1_score(y_test, rf_pred))
    rf_auc = float(roc_auc_score(y_test, rf_proba))
    rf_cm = confusion_matrix(y_test, rf_pred).tolist()

    print("\n==================== RANDOM FOREST RESULTS ====================")
    print(f"Accuracy:  {rf_acc * 100:.2f}%")
    print(f"Precision: {rf_prec * 100:.2f}%")
    print(f"Recall:    {rf_rec * 100:.2f}%")
    print(f"F1-Score:  {rf_f1 * 100:.2f}%")
    print(f"ROC-AUC:   {rf_auc * 100:.2f}%")

    # Step 8: Save Model Artifacts
    os.makedirs(Config.MODELS_DIR, exist_ok=True)
    
    print("\n[*] Saving model artifacts to:", Config.MODELS_DIR)
    joblib.dump(lr_model, Config.MODEL_PATH)
    joblib.dump(rf_model, Config.RF_MODEL_PATH)
    joblib.dump(vectorizer, Config.VECTORIZER_PATH)
    joblib.dump(scaler, os.path.join(Config.MODELS_DIR, "scaler.joblib"))

    # Feature configuration metadata
    feature_config = {
        "text_features": "TF-IDF (1,2-grams, sublinear_tf)",
        "vocabulary_size": len(vectorizer.vocabulary_),
        "numerical_feature_count": len(FEATURE_NAMES),
        "numerical_features": FEATURE_NAMES,
        "primary_model_type": "Logistic Regression (L2 regularized)",
        "comparator_model_type": "Random Forest Classifier (120 estimators)",
        "train_samples": int(len(train_idx)),
        "test_samples": int(len(test_idx)),
        "total_samples": int(len(df))
    }
    with open(Config.FEATURE_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(feature_config, f, indent=4)

    # Real Metrics
    metrics_data = {
        "primary_model": {
            "name": "Logistic Regression",
            "accuracy": round(lr_acc * 100, 2),
            "precision": round(lr_prec * 100, 2),
            "recall": round(lr_rec * 100, 2),
            "f1_score": round(lr_f1 * 100, 2),
            "roc_auc": round(lr_auc * 100, 2),
            "confusion_matrix": {
                "true_negative": lr_cm[0][0],
                "false_positive": lr_cm[0][1],
                "false_negative": lr_cm[1][0],
                "true_positive": lr_cm[1][1]
            }
        },
        "comparator_model": {
            "name": "Random Forest",
            "accuracy": round(rf_acc * 100, 2),
            "precision": round(rf_prec * 100, 2),
            "recall": round(rf_rec * 100, 2),
            "f1_score": round(rf_f1 * 100, 2),
            "roc_auc": round(rf_auc * 100, 2),
            "confusion_matrix": {
                "true_negative": rf_cm[0][0],
                "false_positive": rf_cm[0][1],
                "false_negative": rf_cm[1][0],
                "true_positive": rf_cm[1][1]
            }
        },
        "dataset_summary": {
            "total_records": len(df),
            "train_samples": len(train_idx),
            "test_samples": len(test_idx),
            "phishing_count": int(label_counts.get("phishing", 0)),
            "safe_count": int(label_counts.get("safe", 0)),
            "balance_ratio": f"{int(label_counts.get('phishing', 0))}:{int(label_counts.get('safe', 0))}"
        }
    }
    with open(Config.METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=4)

    print("[*] Successfully trained and saved all models and metrics!")
    return metrics_data

if __name__ == "__main__":
    train_system_models()

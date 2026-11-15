"""
Email NLP Model Training & Benchmarking Pipeline (Phase 4)
==========================================================
Trains and compares NLP text classification algorithms for phishing email detection:
1. TF-IDF + Multinomial Naive Bayes
2. TF-IDF + Logistic Regression (L2 Regularized)
3. TF-IDF + Random Forest Classifier

Enforces strict zero data leakage by fitting TF-IDF vocabulary exclusively on train split.
Selects champion model by F1-Score and saves vectorizer and model via Joblib.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

from ml.feature_extraction.email_features import clean_text_for_nlp

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "datasets", "processed")
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "saved_models")
os.makedirs(SAVED_MODELS_DIR, exist_ok=True)


def train_and_evaluate_email_models():
    print("=" * 70)
    print("PHASE 4: EMAIL NLP CLASSIFIER TRAINING & BENCHMARKING")
    print("=" * 70)

    # 1. Load train and test splits
    train_path = os.path.join(DATA_DIR, "email_train.csv")
    test_path = os.path.join(DATA_DIR, "email_test.csv")

    print(f"\n[+] Loading datasets from:\n    Train: {train_path}\n    Test:  {test_path}")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    # 2. Text preprocessing
    print("[+] Preprocessing email text (subject + body) via NLTK pipeline...")
    train_raw = (df_train["subject"].fillna("") + " " + df_train["body"].fillna("")).tolist()
    test_raw = (df_test["subject"].fillna("") + " " + df_test["body"].fillna("")).tolist()

    X_train_text = [clean_text_for_nlp(t) for t in train_raw]
    X_test_text = [clean_text_for_nlp(t) for t in test_raw]
    y_train = df_train["label"].values.astype(np.int32)
    y_test = df_test["label"].values.astype(np.int32)

    print(f"    - Cleaned train samples: {len(X_train_text)} (Phishing: {sum(y_train == 1)}, Benign: {sum(y_train == 0)})")
    print(f"    - Cleaned test samples:  {len(X_test_text)} (Phishing: {sum(y_test == 1)}, Benign: {sum(y_test == 0)})")

    # 3. Fit TF-IDF Vectorizer strictly on train split
    print("[+] Fitting TF-IDF Vectorizer (n-grams: 1-2, sublinear_tf=True)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        max_features=2500,
        min_df=1
    )
    X_train_vec = vectorizer.fit_transform(X_train_text)
    X_test_vec = vectorizer.transform(X_test_text)
    print(f"    - Vocabulary size: {len(vectorizer.vocabulary_)} n-grams")

    # 4. Model candidates
    models = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Logistic Regression": LogisticRegression(C=2.0, max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    }

    results = {}
    best_f1 = -1.0
    champion_name = None
    champion_model = None

    print("\n[+] Training & Evaluating NLP Algorithms...")
    print("-" * 75)
    print(f"{'Algorithm':<25} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9} | {'ROC-AUC':<9}")
    print("-" * 75)

    for name, model in models.items():
        # Train
        model.fit(X_train_vec, y_train)

        # Predict
        y_pred = model.predict(X_test_vec)
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test_vec)[:, 1]
        else:
            y_proba = y_pred

        # Metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_proba)
        cm = confusion_matrix(y_test, y_pred).tolist()

        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(auc), 4),
            "confusion_matrix": cm
        }

        print(f"{name:<25} | {acc:<9.4f} | {prec:<9.4f} | {rec:<9.4f} | {f1:<9.4f} | {auc:<9.4f}")

        # Update champion based on F1-score (prefer Logistic Regression or Random Forest on tie)
        if f1 > best_f1 or (f1 == best_f1 and name == "Logistic Regression"):
            best_f1 = f1
            champion_name = name
            champion_model = model

    print("-" * 75)
    print(f"\n[+] Champion Email Model Selected: '{champion_name}' with F1-Score: {best_f1:.4f}")

    # 5. Serialize Champion Model, Vectorizer & Metrics
    champion_path = os.path.join(SAVED_MODELS_DIR, "email_model_champion.joblib")
    vec_path = os.path.join(SAVED_MODELS_DIR, "email_tfidf_vectorizer.joblib")
    joblib.dump(champion_model, champion_path)
    joblib.dump(vectorizer, vec_path)
    print(f"[+] Saved champion email model to: {champion_path}")
    print(f"[+] Saved TF-IDF vectorizer to:    {vec_path}")

    metadata = {
        "champion_name": champion_name,
        "vocabulary_size": len(vectorizer.vocabulary_),
        "models_benchmarked": results
    }
    metadata_path = os.path.join(SAVED_MODELS_DIR, "email_models_evaluation.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved email evaluation metrics to: {metadata_path}")

    return metadata


if __name__ == "__main__":
    train_and_evaluate_email_models()

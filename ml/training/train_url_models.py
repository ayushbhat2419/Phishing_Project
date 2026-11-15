"""
Multi-Model URL Detection Training & Benchmarking Pipeline (Phase 3)
===================================================================
Trains and compares classification algorithms:
1. Logistic Regression (L2 Regularized)
2. Decision Tree Classifier
3. Random Forest Classifier
4. Gradient Boosting / XGBoost Classifier

Evaluates on test set via:
- Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix
Selects champion model by F1-Score and saves via Joblib to ml/saved_models/.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

# Optional XGBoost import with safe fallback
HAVE_XGBOOST = False
try:
    from xgboost import XGBClassifier
    # Verify libxgboost loads properly
    _test_xgb = XGBClassifier(n_estimators=1)
    HAVE_XGBOOST = True
except Exception as e:
    HAVE_XGBOOST = False

from ml.feature_extraction.url_features import extract_url_features, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "datasets", "processed")
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "saved_models")
os.makedirs(SAVED_MODELS_DIR, exist_ok=True)


def build_feature_matrix(df: pd.DataFrame):
    """Computes the 18-feature matrix from a dataframe of URLs."""
    feature_rows = []
    for url in df["url"]:
        feats = extract_url_features(url)
        feature_rows.append([feats[col] for col in FEATURE_NAMES])
    X = np.array(feature_rows, dtype=np.float32)
    y = df["label"].values.astype(np.int32)
    return X, y


def train_and_evaluate_url_models():
    print("=" * 70)
    print("PHASE 3: MULTI-MODEL URL CLASSIFIER TRAINING & BENCHMARKING")
    print("=" * 70)

    # 1. Load train and test data
    train_path = os.path.join(DATA_DIR, "url_train.csv")
    test_path = os.path.join(DATA_DIR, "url_test.csv")
    
    print(f"\n[+] Loading datasets from:\n    Train: {train_path}\n    Test:  {test_path}")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    # 2. Extract features
    print(f"[+] Extracting {len(FEATURE_NAMES)} features across train and test sets...")
    X_train, y_train = build_feature_matrix(df_train)
    X_test, y_test = build_feature_matrix(df_test)
    print(f"    - X_train shape: {X_train.shape}, y_train class 1: {sum(y_train == 1)}, class 0: {sum(y_train == 0)}")
    print(f"    - X_test shape:  {X_test.shape}, y_test class 1: {sum(y_test == 1)}, class 0: {sum(y_test == 0)}")

    # 3. Model candidate definitions
    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, random_state=42, C=1.0))
        ]),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=6,
            min_samples_split=4,
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=3,
            random_state=42
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.08,
            max_depth=5,
            subsample=0.85,
            random_state=42
        )
    }

    if HAVE_XGBOOST:
        models["XGBoost"] = XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            eval_metric="logloss",
            random_state=42
        )

    results = {}
    best_f1 = -1.0
    champion_name = None
    champion_model = None

    print("\n[+] Training & Evaluating Algorithms...")
    print("-" * 75)
    print(f"{'Algorithm':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9} | {'ROC-AUC':<9}")
    print("-" * 75)

    for name, model in models.items():
        # Train
        model.fit(X_train, y_train)

        # Predict
        y_pred = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)[:, 1]
        else:
            y_proba = y_pred

        # Compute metrics
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

        print(f"{name:<22} | {acc:<9.4f} | {prec:<9.4f} | {rec:<9.4f} | {f1:<9.4f} | {auc:<9.4f}")

        # Update champion based on F1-score (prefer ensemble Random Forest on tie)
        if f1 > best_f1 or (f1 == best_f1 and name == "Random Forest"):
            best_f1 = f1
            champion_name = name
            champion_model = model

    print("-" * 75)
    print(f"\n[+] Champion URL Model Selected: '{champion_name}' with F1-Score: {best_f1:.4f}")

    # 4. Serialize Champion Model & Metadata
    champion_path = os.path.join(SAVED_MODELS_DIR, "url_model_champion.joblib")
    joblib.dump(champion_model, champion_path)
    print(f"[+] Saved champion URL model to: {champion_path}")

    # Also save Random Forest for tree-based SHAP explanations
    rf_path = os.path.join(SAVED_MODELS_DIR, "url_model_random_forest.joblib")
    joblib.dump(models["Random Forest"], rf_path)

    # Save feature metadata & metrics
    metadata = {
        "champion_name": champion_name,
        "feature_names": FEATURE_NAMES,
        "models_benchmarked": results
    }
    metadata_path = os.path.join(SAVED_MODELS_DIR, "url_models_evaluation.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved URL evaluation metrics to: {metadata_path}")

    return metadata


if __name__ == "__main__":
    train_and_evaluate_url_models()

import os
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.utils.class_weight import compute_class_weight

from xgboost import XGBClassifier

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features


# =========================================================
# DATASET BUILDER
# =========================================================

def build_dataset(malware_files, benign_files):
    X, y = [], []

    def process(path, label):
        try:
            feats = extract_features_from_binary(path)
            vec = vectorize_features(feats)
            X.append(vec)
            y.append(label)
        except Exception as e:
            print(f"[!] Skipping {path} → {e}")

    for p in malware_files:
        process(p, 1)

    for p in benign_files:
        process(p, 0)

    print("\nLoaded samples:", len(X))
    return np.array(X), np.array(y)


# =========================================================
# TRAIN RANDOM FOREST MODEL
# =========================================================

def train_random_forest(X, y):

    print("\nTraining SINGLE Random Forest Model...")

    # Compute class weights
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    class_weight = dict(zip(classes, weights))

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        class_weight=class_weight,
        n_jobs=-1,
        random_state=42
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = []

    for tr, te in cv.split(X, y):
        model.fit(X[tr], y[tr])
        preds = model.predict(X[te])
        scores.append(f1_score(y[te], preds))

    print("RF CV F1 Score:", np.mean(scores))

    model.fit(X, y)
    return model


# =========================================================
# TRAIN XGBOOST MODEL
# =========================================================

def train_xgboost(X, y):

    print("\nTraining SINGLE XGBoost Model...")

    pos = (y == 1).sum()
    neg = (y == 0).sum()
    scale_pos_weight = neg / pos

    model = XGBClassifier(
        n_estimators=350,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
        eval_metric="logloss"
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = []

    for tr, te in cv.split(X, y):
        model.fit(X[tr], y[tr])
        preds = model.predict(X[te])
        scores.append(f1_score(y[te], preds))

    print("XGB CV F1 Score:", np.mean(scores))

    model.fit(X, y)
    return model


# =========================================================
# MAIN TRAINING PIPELINE
# =========================================================

if __name__ == "__main__":

    malware_dir = "samples/ransomware"
    benign_dir = "samples/benign1"

    malware_files = [os.path.join(malware_dir, f) for f in os.listdir(malware_dir)]
    benign_files = [os.path.join(benign_dir, f) for f in os.listdir(benign_dir)]

    print("Building dataset...")

    X, y = build_dataset(malware_files, benign_files)

    print("Dataset shape:", X.shape)

    # =============================
    # TRAIN MODELS
    # =============================

    rf_model = train_random_forest(X, y)
    xgb_model = train_xgboost(X, y)

    # =============================
    # SAVE MODELS
    # =============================

    joblib.dump(rf_model, "rf_single_model.joblib")
    joblib.dump(xgb_model, "xgb_single_model.joblib")

    print("\nModels saved successfully:")
    print(" • rf_single_model.joblib")
    print(" • xgb_single_model.joblib")
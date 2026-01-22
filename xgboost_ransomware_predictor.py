import os
import numpy as np
import joblib
import xgboost as xgb

from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features


# --------------------------------------------------
# CONFIG
# --------------------------------------------------
RANSOMWARE_DIR = "samples/ransomware"
BENIGN_DIR = "samples/benign1"

MODEL_OUT = "xgb_model.joblib"

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin", ".ransom", "")

N_SPLITS = 5
RANDOM_STATE = 42


# --------------------------------------------------
# FILE COLLECTION
# --------------------------------------------------
def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            path = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in SUPPORTED_EXTENSIONS or "." not in f:
                files.append(path)
    return files


# --------------------------------------------------
# DATASET BUILDER
# --------------------------------------------------
def build_dataset(ransomware_files, benign_files):
    X, y = [], []

    for path in ransomware_files:
        try:
            feats = extract_features_from_binary(path)
            vec = vectorize_features(feats)
            X.append(vec)
            y.append(1)
        except Exception as e:
            print(f"[SKIP][RANSOMWARE] {path} → {e}")

    for path in benign_files:
        try:
            feats = extract_features_from_binary(path)
            vec = vectorize_features(feats)
            X.append(vec)
            y.append(0)
        except Exception as e:
            print(f"[SKIP][BENIGN] {path} → {e}")

    return np.array(X), np.array(y)


# --------------------------------------------------
# TRAIN XGBOOST
# --------------------------------------------------
def train_xgboost(X, y):
    # ---- STEP 2 ASSERTIONS (CRITICAL) ----
    assert len(X) > 0, "❌ Dataset is empty"
    assert (y == 1).sum() > 0, "❌ No ransomware samples"
    assert (y == 0).sum() > 0, "❌ No benign samples"

    pos = (y == 1).sum()
    neg = (y == 0).sum()
    scale_pos_weight = neg / max(pos, 1)

    print(f"Ransomware samples : {pos}")
    print(f"Benign samples     : {neg}")
    print(f"scale_pos_weight  : {scale_pos_weight:.2f}")

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    cv = StratifiedKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    f1_scores = []

    for fold, (tr, te) in enumerate(cv.split(X, y), 1):
        model.fit(X[tr], y[tr])
        preds = model.predict(X[te])
        f1 = f1_score(y[te], preds)
        f1_scores.append(f1)
        print(f"[Fold {fold}] F1 = {f1:.3f}")

    print(f"\nMean CV F1-score: {np.mean(f1_scores):.3f}")

    model.fit(X, y)
    return model


# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == "__main__":

    ransomware_files = collect_files(RANSOMWARE_DIR)
    benign_files = collect_files(BENIGN_DIR)

    print(f"Loaded {len(ransomware_files)} ransomware files")
    print(f"Loaded {len(benign_files)} benign files")

    X, y = build_dataset(ransomware_files, benign_files)

    model = train_xgboost(X, y)

    joblib.dump(model, MODEL_OUT)
    print(f"\n✅ XGBoost model saved to {MODEL_OUT}")

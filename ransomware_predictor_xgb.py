import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES


# =============================
# DATASET BUILDER
# =============================

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

    print("Loaded samples:", len(X))
    return np.array(X), np.array(y)


# =============================
# TRAIN SINGLE XGB MODEL
# =============================

def train_xgb_model(X, y, name):

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

    print(f"\nTraining {name} Model...")

    for tr, te in cv.split(X, y):
        model.fit(X[tr], y[tr])
        preds = model.predict(X[te])
        scores.append(f1_score(y[te], preds))

    print(f"{name} CV F1:", np.mean(scores))

    model.fit(X, y)
    return model


# =============================
# MAIN
# =============================

if __name__ == "__main__":
    import os

    malware_dir = "samples/ransomware"
    benign_dir = "samples/benign1"

    malware_files = [os.path.join(malware_dir, f) for f in os.listdir(malware_dir)]
    benign_files = [os.path.join(benign_dir, f) for f in os.listdir(benign_dir)]

    X, y = build_dataset(malware_files, benign_files)

    # =============================
    # SPLIT FEATURE GROUPS
    # =============================

    X1 = X[:, MODEL1_INDICES]   # behavior
    X2 = X[:, MODEL2_INDICES]   # artifact

    print("Behavior feature shape:", X1.shape)
    print("Artifact feature shape:", X2.shape)

    # =============================
    # TRAIN BOTH MODELS
    # =============================

    model1 = train_xgb_model(X1, y, "Behavior")
    model2 = train_xgb_model(X2, y, "Artifact")

    # =============================
    # SAVE MODELS
    # =============================

    joblib.dump(model1, "xgb_behavior_model.joblib")
    joblib.dump(model2, "xgb_artifact_model.joblib")

    print("\nBoth XGBoost models saved successfully")
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.utils.class_weight import compute_class_weight

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
# TRAIN RANDOM FOREST MODEL
# =============================

def train_rf_model(X, y, name):

    # ---- Class imbalance handling ----
    classes = np.unique(y)
    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y
    )
    class_weight = dict(zip(classes, weights))

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight=class_weight,
        n_jobs=-1,
        random_state=42
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

    # -----------------------------
    # Build dataset
    # -----------------------------
    X, y = build_dataset(malware_files, benign_files)

    # -----------------------------
    # Split feature groups
    # -----------------------------
    X1 = X[:, MODEL1_INDICES]   # Behavior
    X2 = X[:, MODEL2_INDICES]   # Artifact

    print("Behavior feature shape:", X1.shape)
    print("Artifact feature shape:", X2.shape)

    # -----------------------------
    # Train both models
    # -----------------------------
    model1 = train_rf_model(X1, y, "Behavior")
    model2 = train_rf_model(X2, y, "Artifact")

    # -----------------------------
    # Save models
    # -----------------------------
    joblib.dump(model1, "rf_behavior_model.joblib")
    joblib.dump(model2, "rf_artifact_model.joblib")

    print("\nBoth Random Forest models saved successfully")
# ransomware_predictor.py

import numpy as np
from data_augmentation import apply_smote, apply_mixup
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
import joblib
from sklearn.utils.class_weight import compute_class_weight
from tqdm import tqdm

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features


def build_dataset(malware_files, benign_files):
    X, y = [], []

    def process_file(path, label):
        try:
            feats = extract_features_from_binary(path)
            vec = vectorize_features(feats)
            X.append(vec)
            y.append(label)
        except Exception as e:
            print(f"[!] Skipping file due to error: {path}")
            print(f"    Reason: {e}")

    for path in malware_files:
        process_file(path, label=1)

    for path in benign_files:
        process_file(path, label=0)

    print(f"\nDataset build complete: {len(X)} samples loaded")
    return np.array(X), np.array(y)


def train_random_forest(X, y):
    """
    Train Random Forest with progress bar and proper class weighting.
    """

    n_trees = 100

    # ---- compute class weights ONCE ----
    classes = np.unique(y)
    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y
    )
    class_weight = dict(zip(classes, weights))

    model = RandomForestClassifier(
        n_estimators=1,
        warm_start=True,
        class_weight=class_weight,   # ← FIXED
        n_jobs=-1,
        random_state=42
    )

    print("Training Random Forest...")
    for i in tqdm(range(1, n_trees + 1), desc="Training progress", unit="tree"):
        model.n_estimators = i
        model.fit(X, y)

    print("Training completed")
    return model



def predict_file(model, filepath):
    feats = extract_features_from_binary(filepath)
    vec = vectorize_features(feats)
    return model.predict([vec])[0]

if __name__ == "__main__":
    import os

    malware_dir = "samples/ransomware"
    benign_dir = "samples/benign1"

    malware_files = [
        os.path.join(malware_dir, f)
        for f in os.listdir(malware_dir)
    ]

    benign_files = [
        os.path.join(benign_dir, f)
        for f in os.listdir(benign_dir)
    ]

    print("Malware files:", malware_files)
    print("Benign files:", benign_files)

    X, y = build_dataset(malware_files, benign_files)

    print("Dataset shape:", X.shape)
    print("Labels:", y)


    # Step 1: SMOTE (balance)
    X, y = apply_smote(X, y)

    # Step 2: MixUp (generalization)
    X, y = apply_mixup(X, y, alpha=0.3)

    model = train_random_forest(X, y)

    joblib.dump(model, "rf_model.joblib")
    print("Model saved to rf_model.joblib")

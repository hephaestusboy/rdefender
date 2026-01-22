# ransomware_predictor.py

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
# from sklearn.ensemble import RandomForestClassifier
from tqdm import tqdm
from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features


def build_dataset(malware_files, benign_files):
    X, y = [], []

    for path in malware_files:
        feats = extract_features_from_binary(path)
        vec = vectorize_features(feats)
        X.append(vec)
        y.append(1)

    for path in benign_files:
        feats = extract_features_from_binary(path)
        vec = vectorize_features(feats)
        X.append(vec)
        y.append(0)

    return np.array(X), np.array(y)


def train_random_forest(X, y):
    """
    Train Random Forest with progress indicator.
    """

    n_trees = 100  # keep small for now

    model = RandomForestClassifier(
        n_estimators=1,        # start with 1 tree
        warm_start=True,       # allow incremental growth
        class_weight="balanced",
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

# test_ransomware_predictor.py

import os
import joblib

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")


def load_model(model_path="rf_model.joblib"):
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model file not found: {model_path}. Train the model first."
        )
    return joblib.load(model_path)


def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files


def predict_file(model, filepath):
    feats = extract_features_from_binary(filepath)
    vec = vectorize_features(feats)

    probs = model.predict_proba([vec])[0]
    pred = model.predict([vec])[0]

    ransomware_prob = probs[1]  # class 1 = ransomware
    return pred, ransomware_prob



if __name__ == "__main__":

    model = load_model("rf_model.joblib")
    print("Model loaded")

    # ---- ONLY ONE DIRECTORY ----
    test_dir = "samples/test1"   # ← change this to your test directory

    test_files = collect_files(test_dir)

    print(f"Found {len(test_files)} files in test directory")

    print("\n--- TEST DIRECTORY SCAN ---")
    for f in test_files:
        try:
            pred, prob = predict_file(model, f)

            label = "RANSOMWARE" if pred == 1 else "BENIGN"

            print(
                f"{f} → {label} "
                f"({prob * 100:.2f}% ransomware)"
            )

        except Exception as e:
            print(f"{f} → ERROR: {e}")




import os
import joblib

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

# -----------------------------
# CONFIG
# -----------------------------
MALWARE_THRESHOLD = 0.6
SUSPICIOUS_THRESHOLD = 0.4


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
    ransomware_prob = probs[1]

    if ransomware_prob >= MALWARE_THRESHOLD:
        label = "RANSOMWARE"
    elif ransomware_prob >= SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"
    else:
        label = "BENIGN"

    return label, ransomware_prob


if __name__ == "__main__":

    # model = load_model("rf_model.joblib")
    model = load_model("xgb_model.joblib")

    print("Model loaded")

    ransomware_dir = "samples/test/ransomware"
    benign_dir = "samples/test/benign"

    ransomware_files = collect_files(ransomware_dir)
    benign_files = collect_files(benign_dir)

    # -----------------------------
    # CONFUSION MATRIX COUNTERS
    # (Suspicious is tracked separately)
    # -----------------------------
    TP = FN = FP = TN = 0
    suspicious_count = 0

    print("\n--- TEST: RANSOMWARE FILES (label = 1) ---")
    for f in ransomware_files:
        try:
            label, prob = predict_file(model, f)

            if label == "RANSOMWARE":
                TP += 1
            elif label == "BENIGN":
                FN += 1
            else:
                suspicious_count += 1

            print(f"{f} → {label} ({prob * 100:.2f}%)")

        except Exception as e:
            print(f"{f} → ERROR: {e}")

    print("\n--- TEST: BENIGN FILES (label = 0) ---")
    for f in benign_files:
        try:
            label, prob = predict_file(model, f)

            if label == "BENIGN":
                TN += 1
            elif label == "RANSOMWARE":
                FP += 1
            else:
                suspicious_count += 1

            print(f"{f} → {label} ({prob * 100:.2f}%)")

        except Exception as e:
            print(f"{f} → ERROR: {e}")

    # -----------------------------
    # METRICS (Suspicious excluded)
    # -----------------------------
    total = TP + TN + FP + FN

    accuracy = (TP + TN) / total if total else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    fpr = FP / (FP + TN) if (FP + TN) else 0
    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0


    print("\n================ EVALUATION SUMMARY ================")
    print(f"Malware threshold     : {MALWARE_THRESHOLD}")
    print(f"Suspicious threshold  : {SUSPICIOUS_THRESHOLD}")
    print(f"Total evaluated       : {total}")
    print(f"Accuracy              : {accuracy:.3f}")
    print(f"Ransomware Recall     : {recall:.3f}")
    print(f"False Positive Rate   : {fpr:.3f}")
    print(f"Suspicious samples    : {suspicious_count}")
    print(f"Precision             : {precision:.3f}")
    print(f"F1 Score              : {f1:.3f}")
    
    print("\nConfusion Matrix:")
    print(f"TP (Ransomware → Ransomware): {TP}")
    print(f"FN (Ransomware → Benign)    : {FN}")
    print(f"FP (Benign → Ransomware)    : {FP}")
    print(f"TN (Benign → Benign)        : {TN}")




import os
import joblib
import numpy as np

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES


SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

# =============================
# CONFIG
# =============================
MALWARE_THRESHOLD = 0.65
SUSPICIOUS_THRESHOLD = 0.45

BEHAVIOR_WEIGHT = 0.8
ARTIFACT_WEIGHT = 0.2

AGREEMENT_THRESHOLD = 0.25




# =============================
# LOAD MODELS
# =============================

def load_models():
    m1 = joblib.load("xgb_behavior_model.joblib")
    m2 = joblib.load("xgb_artifact_model.joblib")
    return m1, m2


# =============================
# FILE COLLECTION
# =============================

def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files


# =============================
# PREDICTION
# =============================

def predict_file(model1, model2, filepath):

    feats = extract_features_from_binary(filepath)
    vec = np.array(vectorize_features(feats))

    # Split feature groups
    vec1 = vec[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec[MODEL2_INDICES].reshape(1, -1)

    # Get probabilities
    p1 = model1.predict_proba(vec1)[0][1]
    p2 = model2.predict_proba(vec2)[0][1]

    # Weighted fusion
    # ===== BEHAVIOR DOMINANT FUSION =====

    if p1 < 0.35:
        final_prob = p1

    elif p1 > 0.75:
        final_prob = p1

    else:
        final_prob = BEHAVIOR_WEIGHT * p1 + ARTIFACT_WEIGHT * p2
    # Classification
    if final_prob >= MALWARE_THRESHOLD:
        label = "RANSOMWARE"
    elif final_prob >= SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"
    else:
        label = "BENIGN"

    return label, final_prob, p1, p2


# =============================
# MAIN EVALUATION
# =============================

if __name__ == "__main__":

    model1, model2 = load_models()
    print("Both models loaded successfully")

    ransomware_dir = "samples/test/ransomware"
    benign_dir = "samples/test/benign"

    ransomware_files = collect_files(ransomware_dir)
    benign_files = collect_files(benign_dir)

    TP = FN = FP = TN = 0
    suspicious_count = 0

    # =============================
    # TEST RANSOMWARE FILES
    # =============================

    print("\n--- TEST: RANSOMWARE FILES ---")

    for f in ransomware_files:
        try:
            label, prob, p1, p2 = predict_file(model1, model2, f)

            if label == "RANSOMWARE":
                TP += 1
            elif label == "BENIGN":
                FN += 1
            else:
                suspicious_count += 1

            print(
                f"{f} → {label} | "
                f"Final:{prob*100:.2f}% "
                f"(Behavior:{p1*100:.1f}%, Artifact:{p2*100:.1f}%)"
            )

        except Exception as e:
            print(f"{f} → ERROR: {e}")

    # =============================
    # TEST BENIGN FILES
    # =============================

    print("\n--- TEST: BENIGN FILES ---")

    for f in benign_files:
        try:
            label, prob, p1, p2 = predict_file(model1, model2, f)

            if label == "BENIGN":
                TN += 1
            elif label == "RANSOMWARE":
                FP += 1
            else:
                suspicious_count += 1

            print(
                f"{f} → {label} | "
                f"Final:{prob*100:.2f}% "
                f"(Behavior:{p1*100:.1f}%, Artifact:{p2*100:.1f}%)"
            )

        except Exception as e:
            print(f"{f} → ERROR: {e}")

    # =============================
    # METRICS
    # =============================

    total = TP + TN + FP + FN

    accuracy = (TP + TN) / total if total else 0
    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    fpr = FP / (FP + TN) if (FP + TN) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    print("\n================ FINAL EVALUATION ================")
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
    print(f"TP: {TP}")
    print(f"FN: {FN}")
    print(f"FP: {FP}")
    print(f"TN: {TN}")

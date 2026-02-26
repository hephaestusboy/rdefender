import os
import joblib
import numpy as np

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

# =============================
# CONFIG
# =============================

MALWARE_THRESHOLD = 0.6
SUSPICIOUS_THRESHOLD = 0.45

BEHAVIOR_WEIGHT = 0.8
ARTIFACT_WEIGHT = 0.2

LOW_BEHAVIOR_TRUST = 0.35
HIGH_BEHAVIOR_TRUST = 0.75


# =============================
# LOAD ALL MODELS
# =============================

def load_models():
    models = {
        "rf_behav": joblib.load("rf_behavior_model.joblib"),
        "rf_art": joblib.load("rf_artifact_model.joblib"),
        "xgb_behav": joblib.load("xgb_behavior_model.joblib"),
        "xgb_art": joblib.load("xgb_artifact_model.joblib"),
    }
    return models


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

def predict_file(models, filepath):

    feats = extract_features_from_binary(filepath)
    vec = np.array(vectorize_features(feats))

    vec1 = vec[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec[MODEL2_INDICES].reshape(1, -1)

    # ---- BEHAVIOR SCORES ----
    rf_b = models["rf_behav"].predict_proba(vec1)[0][1]
    xgb_b = models["xgb_behav"].predict_proba(vec1)[0][1]
    behavior_score = 0.5 * rf_b + 0.5 * xgb_b

    # ---- ARTIFACT SCORES ----
    rf_a = models["rf_art"].predict_proba(vec2)[0][1]
    xgb_a = models["xgb_art"].predict_proba(vec2)[0][1]
    artifact_score = 0.5 * rf_a + 0.5 * xgb_a

    p1=rf_b
    p2=xgb_b
    # =============================
    # CONFIDENCE-AWARE FUSION
    # =============================

    confidence = abs(p1 - 0.5) * 2

    # when behavior confident → trust it more
    behavior_weight = 0.6 + 0.4 * confidence

    artifact_weight = 1 - behavior_weight

    final_prob = behavior_weight * p1 + artifact_weight * p2

    # =============================
    # CLASSIFICATION
    # =============================

    if final_prob >= MALWARE_THRESHOLD:
        label = "RANSOMWARE"
    elif final_prob >= SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"
    else:
        label = "BENIGN"

    return label, final_prob, behavior_score, artifact_score


# =============================
# MAIN EVALUATION
# =============================

if __name__ == "__main__":

    models = load_models()
    print("Hybrid Ensemble Loaded Successfully")

    ransomware_files = collect_files("samples/test/ransomware")
    benign_files = collect_files("samples/test/benign")

    TP = FN = FP = TN = 0
    suspicious_count = 0

    print("\n--- TEST: RANSOMWARE FILES ---")

    for f in ransomware_files:
        try:
            label, prob, pb, pa = predict_file(models, f)

            if label == "RANSOMWARE":
                TP += 1
            elif label == "BENIGN":
                FN += 1
            else:
                suspicious_count += 1

            print(f"{f} → {label} | Final:{prob*100:.2f}% "
                  f"(Behav:{pb*100:.1f}%, Art:{pa*100:.1f}%)")

        except Exception as e:
            print(f"{f} → ERROR: {e}")

    print("\n--- TEST: BENIGN FILES ---")

    for f in benign_files:
        try:
            label, prob, pb, pa = predict_file(models, f)

            if label == "BENIGN":
                TN += 1
            elif label == "RANSOMWARE":
                FP += 1
            else:
                suspicious_count += 1

            print(f"{f} → {label} | Final:{prob*100:.2f}% "
                  f"(Behav:{pb*100:.1f}%, Art:{pa*100:.1f}%)")

        except Exception as e:
            print(f"{f} → ERROR: {e}")

    # =============================
    # METRICS
    # =============================

    total = TP + TN + FP + FN

    accuracy = (TP + TN) / total
    precision = TP / (TP + FP)
    recall = TP / (TP + FN)
    fpr = FP / (FP + TN)
    f1 = 2 * precision * recall / (precision + recall)

    print("\n================ FINAL EVALUATION ================")
    print(f"Accuracy      : {accuracy:.3f}")
    print(f"Recall        : {recall:.3f}")
    print(f"Precision     : {precision:.3f}")
    print(f"F1 Score      : {f1:.3f}")
    print(f"False PosRate : {fpr:.3f}")
    print(f"Suspicious    : {suspicious_count}")

    print("\nConfusion Matrix:")
    print(f"TP: {TP}  FN: {FN}")
    print(f"FP: {FP}  TN: {TN}")
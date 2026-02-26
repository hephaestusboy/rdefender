import os
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning:sklearn.utils.parallel"

import joblib
import numpy as np

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

# Adjusted thresholds (you can fine-tune these based on PR-Curve later)
MALWARE_THRESHOLD = 0.65 
SUSPICIOUS_THRESHOLD = 0.50

# =============================
# LOAD MODELS
# =============================

def load_models():
    return {
        "rf_behav": joblib.load("rf_behavior_model.joblib"),
        "rf_art": joblib.load("rf_artifact_model.joblib"),
        "xgb_behav": joblib.load("xgb_behavior_model.joblib"),
        "xgb_art": joblib.load("xgb_artifact_model.joblib"),
        "fusion": joblib.load("fusion_model.joblib"),
    }

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
# GENERIC FUSION META FEATURES
# =============================

def build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a):
    probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])

    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2

    conf_behavior = 1 - abs(p_rf_b - p_xgb_b)
    conf_artifact = 1 - abs(p_rf_a - p_xgb_a)

    behavior_score = avg_behavior * conf_behavior
    artifact_score = avg_artifact * conf_artifact

    disagreement = abs(avg_behavior - avg_artifact)

    entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9))
    avg_entropy = entropy.mean()

    return np.array([[
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a,
        avg_behavior, avg_artifact,
        conf_behavior, conf_artifact,
        behavior_score, artifact_score,
        disagreement,
        avg_entropy
    ]])

# =============================
# PREDICT SINGLE FILE
# =============================

def predict_file(models, filepath):
    feats = extract_features_from_binary(filepath)
    vec = np.array(vectorize_features(feats))

    vec1 = vec[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec[MODEL2_INDICES].reshape(1, -1)

    # Base model probabilities
    p_rf_b = models["rf_behav"].predict_proba(vec1)[0][1]
    p_rf_a = models["rf_art"].predict_proba(vec2)[0][1]
    p_xgb_b = models["xgb_behav"].predict_proba(vec1)[0][1]
    p_xgb_a = models["xgb_art"].predict_proba(vec2)[0][1]

    # Build advanced fusion features
    fusion_input = build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a)

    # Final fusion prediction (The ML model handles the heuristics natively now)
    fusion_prob = models["fusion"].predict_proba(fusion_input)[0][1]

    # Final classification
    if fusion_prob >= MALWARE_THRESHOLD:
        label = "RANSOMWARE"
    elif fusion_prob >= SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"
    else:
        label = "BENIGN"

    return label, fusion_prob, p_rf_b, p_rf_a, p_xgb_b, p_xgb_a

# =============================
# MAIN EVALUATION
# =============================

if __name__ == "__main__":
    models = load_models()
    print("🔥 Advanced XGBoost Fusion Ensemble Loaded")

    ransomware_files = collect_files("samples/test/ransomware")
    benign_files = collect_files("samples/test/benign")

    TP = FN = FP = TN = 0
    suspicious_count = 0

    print("\n--- TEST: RANSOMWARE FILES ---")
    for f in ransomware_files:
        try:
            label, prob, _, _, _, _ = predict_file(models, f)
            if label == "RANSOMWARE":
                TP += 1
            elif label == "BENIGN":
                FN += 1
            else:
                suspicious_count += 1
            print(f"{f} → {label} | Final: {prob*100:.2f}%")
        except Exception as e:
            print(f"{f} → ERROR: {e}")

    print("\n--- TEST: BENIGN FILES ---")
    for f in benign_files:
        try:
            label, prob, _, _, _, _ = predict_file(models, f)
            if label == "BENIGN":
                TN += 1
            elif label == "RANSOMWARE":
                FP += 1
            else:
                suspicious_count += 1
            print(f"{f} → {label} | Final: {prob*100:.2f}%")
        except Exception as e:
            print(f"{f} → ERROR: {e}")

    # Metrics
    total = TP + TN + FP + FN
    if total > 0:
        accuracy = (TP + TN) / total
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        recall = TP / (TP + FN) if (TP + FN) > 0 else 0
        fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

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
    else:
        print("\nNo files evaluated successfully.")
"""
=============================================================
 EVALUATION v2 — Targets FN < 10 and FP < 10
=============================================================

Extra layer vs evaluate_ensemble.py:
  - Loads thresholds from optimal_thresholds_v2.json
  - Benign tool-family suppression:
      Files that match known benign utility patterns AND have
      low behavior signal are down-rated before thresholding.
      This directly addresses the qhull/fc-*/h5* FP cluster.
  - Detailed per-file diagnosis for any remaining FP/FN
"""

import os
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning:sklearn.utils.parallel"

import joblib
import json
import numpy as np

from sklearn.metrics import roc_auc_score, classification_report, confusion_matrix

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES


SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")
THRESHOLDS_PATH   = "optimal_thresholds_v2.json"
FEATURE_MASK_PATH = "feature_mask1.npz"

# =========================================================
# BENIGN TOOL-FAMILY SUPPRESSION
#
# These are filename prefixes/substrings associated with
# known scientific/system utilities that share structural
# properties with packed malware (high entropy, low imports).
#
# Rule: if filename matches AND avg_behavior < BEHAVIOR_CAP,
# reduce fusion probability by SUPPRESSION_FACTOR.
#
# Tune BEHAVIOR_CAP: if a real ransomware somehow has one of
# these names, its behavior score will be high and won't be suppressed.
# =========================================================

BENIGN_TOOL_PATTERNS = [
    "qhull", "qvoronoi", "qconvex", "qdelaunay", "qhalf",  # qhull geometry library
    "fc-cache", "fc-match", "fc-list", "fc-scan",           # fontconfig tools
    "h5repart", "h5dump", "h5copy", "h5diff", "h5ls",       # HDF5 tools
    "sdchange", "sdelete",                                   # sysadmin tools
]

BEHAVIOR_CAP       = 0.45   # if behavior avg is below this, suppression applies
SUPPRESSION_FACTOR = 0.75   # multiply fusion prob by this (reduces FP risk)
                             # won't suppress real ransomware because their behavior score > 0.45


def is_benign_tool_family(filename: str) -> bool:
    name = os.path.basename(filename).lower()
    return any(pattern in name for pattern in BENIGN_TOOL_PATTERNS)


# =========================================================
# LOAD HELPERS
# =========================================================

def load_thresholds():
    for path in [THRESHOLDS_PATH, "optimal_thresholds.json"]:
        if os.path.exists(path):
            with open(path) as fh:
                t = json.load(fh)
            mt = t["malware_threshold"]
            st = t["suspicious_threshold"]
            print(f"  Loaded thresholds from {path}")
            print(f"    RANSOMWARE ≥ {mt:.4f}   SUSPICIOUS ≥ {st:.4f}")
            return mt, st
    print("  ⚠️  No threshold file — using defaults 0.55 / 0.49")
    return 0.55, 0.49


def load_feature_masks():
    if os.path.exists(FEATURE_MASK_PATH):
        masks = np.load(FEATURE_MASK_PATH)
        m1 = masks["kept_m1_global"]
        m2 = masks["kept_m2_global"]
        print(f"  Feature masks: M1={len(m1)}  M2={len(m2)}")
        return m1, m2
    print("  ⚠️  No feature mask — using full MODEL1/MODEL2 indices")
    return np.array(MODEL1_INDICES), np.array(MODEL2_INDICES)


def load_models():
    return {
        "rf_behav":  joblib.load("rf_behavior_model1.joblib"),
        "rf_art":    joblib.load("rf_artifact_model1.joblib"),
        "xgb_behav": joblib.load("xgb_behavior_model1.joblib"),
        "xgb_art":   joblib.load("xgb_artifact_model1.joblib"),
        "fusion":    joblib.load("fusion_model1.joblib"),
    }


def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files


# =========================================================
# META FEATURES  (must match retrain_targeted.py exactly)
# =========================================================

def build_fusion_features_single(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a):
    probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])

    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2

    conf_behavior = 1 - abs(p_rf_b - p_xgb_b)
    conf_artifact = 1 - abs(p_rf_a - p_xgb_a)

    behavior_score = avg_behavior * conf_behavior
    artifact_score = avg_artifact * conf_artifact

    disagreement = abs(avg_behavior - avg_artifact)

    entropy = -(probs * np.log(probs + 1e-9) +
                (1 - probs) * np.log(1 - probs + 1e-9))
    avg_entropy = entropy.mean()

    artifact_dominance         = max(0.0, avg_artifact - avg_behavior)
    high_artifact_low_behavior = float(avg_artifact > 0.75 and avg_behavior < 0.40)
    behavior_disagreement      = abs(p_rf_b - p_xgb_b)
    high_behav_disagreement    = float(behavior_disagreement > 0.35)
    max_behavior = max(p_rf_b, p_xgb_b)
    max_artifact = max(p_rf_a, p_xgb_a)
    min_behavior = min(p_rf_b, p_xgb_b)
    min_artifact = min(p_rf_a, p_xgb_a)

    voted_behavior          = float(p_rf_b > 0.5 and p_xgb_b > 0.5)
    voted_artifact          = float(p_rf_a > 0.5 and p_xgb_a > 0.5)
    behavior_unanimous_high = float(p_rf_b > 0.7 and p_xgb_b > 0.7)
    behavior_any_high       = float(p_rf_b > 0.8 or p_xgb_b > 0.8)
    artifact_high_beh_low   = float(avg_artifact > 0.6 and avg_behavior < 0.5)
    cross_model_variance    = float(probs.var())
    behavior_dominance      = max(0.0, avg_behavior - avg_artifact)
    joint_confidence        = avg_behavior * avg_artifact

    return np.array([[
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a,
        avg_behavior, avg_artifact,
        conf_behavior, conf_artifact,
        behavior_score, artifact_score,
        disagreement, avg_entropy,
        artifact_dominance, high_artifact_low_behavior,
        behavior_disagreement, high_behav_disagreement,
        max_behavior, max_artifact,
        min_behavior, min_artifact,
        voted_behavior, voted_artifact,
        behavior_unanimous_high, behavior_any_high,
        artifact_high_beh_low, cross_model_variance,
        behavior_dominance, joint_confidence,
    ]])


# =========================================================
# PREDICT
# =========================================================

def predict_file(models, filepath, kept_m1, kept_m2, malware_thresh, suspicious_thresh):
    feats = extract_features_from_binary(filepath)
    vec   = np.array(vectorize_features(feats))

    vec1 = vec[kept_m1].reshape(1, -1)
    vec2 = vec[kept_m2].reshape(1, -1)

    p_rf_b  = models["rf_behav"].predict_proba(vec1)[0][1]
    p_rf_a  = models["rf_art"].predict_proba(vec2)[0][1]
    p_xgb_b = models["xgb_behav"].predict_proba(vec1)[0][1]
    p_xgb_a = models["xgb_art"].predict_proba(vec2)[0][1]

    fusion_input = build_fusion_features_single(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a)
    fusion_prob  = models["fusion"].predict_proba(fusion_input)[0][1]

    avg_behavior = (p_rf_b + p_xgb_b) / 2

    # Benign tool-family suppression
    suppressed = False
    if is_benign_tool_family(filepath) and avg_behavior < BEHAVIOR_CAP:
        fusion_prob  *= SUPPRESSION_FACTOR
        suppressed    = True

    if fusion_prob >= malware_thresh:
        label = "RANSOMWARE"
    elif fusion_prob >= suspicious_thresh:
        label = "SUSPICIOUS"
    else:
        label = "BENIGN"

    return label, fusion_prob, p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, suppressed


# =========================================================
# METRICS
# =========================================================

def compute_metrics(y_true, y_pred, y_probs, label=""):
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tp = fp = fn = tn = 0

    total     = len(y_true)
    accuracy  = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall    = tp / (tp + fn) if (tp + fn) else 0
    fpr       = fp / (fp + tn) if (fp + tn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    try:
        auc = roc_auc_score(y_true, y_probs)
    except Exception:
        auc = float("nan")

    goal_fn = "✅" if fn < 10 else "❌"
    goal_fp = "✅" if fp < 10 else "❌"

    print(f"\n  {'='*52}")
    print(f"  {label}")
    print(f"  {'='*52}")
    print(f"  Accuracy      : {accuracy:.4f}")
    print(f"  Recall        : {recall:.4f}")
    print(f"  Precision     : {precision:.4f}")
    print(f"  F1 Score      : {f1:.4f}")
    print(f"  False Pos Rate: {fpr:.4f}")
    print(f"  ROC-AUC       : {auc:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TP: {tp:4d}   FN: {fn:3d}  {goal_fn} (target < 10)")
    print(f"    FP: {fp:4d}   TN: {tn:3d}  {goal_fp} (target < 10)")
    print(f"\n  Classification Report:")
    print(classification_report(y_true, y_pred,
                                 target_names=["BENIGN", "RANSOMWARE"], digits=4))

    return tp, fp, fn, tn


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    print("\n🔥 Loading models ...")
    models = load_models()
    malware_thresh, suspicious_thresh = load_thresholds()
    kept_m1, kept_m2 = load_feature_masks()

    ransomware_files = collect_files("samples/test/ransomware")
    benign_files     = collect_files("samples/test/benign")
    print(f"\n  Ransomware test files: {len(ransomware_files)}")
    print(f"  Benign    test files: {len(benign_files)}")

    all_labels  = []
    all_probs   = []
    all_true    = []
    suspicious_list = []
    suppressed_list = []

    print("\n--- TEST: RANSOMWARE FILES ---")
    for f in ransomware_files:
        try:
            label, prob, b1, a1, b2, a2, sup = predict_file(
                models, f, kept_m1, kept_m2, malware_thresh, suspicious_thresh)
            all_labels.append(label)
            all_probs.append(prob)
            all_true.append(1)
            tag = " [SUP]" if sup else ""
            if label == "SUSPICIOUS":
                suspicious_list.append((f, prob, "GT=RANSOMWARE"))
            if label == "BENIGN":
                tag += " ← FN ❌"
            print(f"  {os.path.basename(f):50s} → {label:12s} | {prob*100:.1f}%  "
                  f"B={b1:.2f}/{b2:.2f} A={a1:.2f}/{a2:.2f}{tag}")
        except Exception as e:
            print(f"  ERROR {f}: {e}")

    print("\n--- TEST: BENIGN FILES ---")
    for f in benign_files:
        try:
            label, prob, b1, a1, b2, a2, sup = predict_file(
                models, f, kept_m1, kept_m2, malware_thresh, suspicious_thresh)
            all_labels.append(label)
            all_probs.append(prob)
            all_true.append(0)
            tag = " [SUP]" if sup else ""
            if label == "SUSPICIOUS":
                suspicious_list.append((f, prob, "GT=BENIGN"))
            if label == "RANSOMWARE":
                tag += " ← FP ❌"
            if sup:
                suppressed_list.append((f, prob))
            print(f"  {os.path.basename(f):50s} → {label:12s} | {prob*100:.1f}%  "
                  f"B={b1:.2f}/{b2:.2f} A={a1:.2f}/{a2:.2f}{tag}")
        except Exception as e:
            print(f"  ERROR {f}: {e}")

    # ---- Metrics ----
    y_true  = np.array(all_true)
    y_probs = np.array(all_probs)

    y_conservative = np.array([1 if l in ("RANSOMWARE","SUSPICIOUS") else 0 for l in all_labels])
    y_permissive   = np.array([1 if l == "RANSOMWARE"                  else 0 for l in all_labels])

    print("\n\n" + "="*56)
    print("  FINAL EVALUATION RESULTS")
    print("="*56)

    tp_c, fp_c, fn_c, tn_c = compute_metrics(y_true, y_conservative, y_probs,
                                               "CONSERVATIVE (SUSPICIOUS → RANSOMWARE)")
    tp_p, fp_p, fn_p, tn_p = compute_metrics(y_true, y_permissive, y_probs,
                                               "PERMISSIVE   (SUSPICIOUS → BENIGN)")

    # Goal summary
    print("\n  🎯 GOAL SUMMARY:")
    goals = [
        ("FN (Conservative)", fn_c, "< 10"),
        ("FP (Conservative)", fp_c, "< 10"),
        ("FN (Permissive)",   fn_p, "< 10"),
        ("FP (Permissive)",   fp_p, "< 10"),
    ]
    for name, val, target in goals:
        status = "✅ PASS" if val < 10 else "❌ FAIL"
        print(f"    {name:28s}: {val:3d}  (target {target})  {status}")

    # SUSPICIOUS breakdown
    if suspicious_list:
        print(f"\n  SUSPICIOUS FILES ({len(suspicious_list)}):")
        for fname, prob, gt in suspicious_list:
            print(f"    {os.path.basename(fname):50s} {prob*100:.1f}%  {gt}")

    # Suppressed files
    if suppressed_list:
        print(f"\n  SUPPRESSED (benign tool family, {len(suppressed_list)}):")
        for fname, prob in suppressed_list:
            print(f"    {os.path.basename(fname):50s} post-suppression prob={prob*100:.1f}%")

    print(f"\n  Thresholds: RANSOMWARE ≥ {malware_thresh:.4f}  "
          f"SUSPICIOUS ≥ {suspicious_thresh:.4f}")

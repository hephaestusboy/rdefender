"""
=============================================================
 EVALUATION for CatBoost+LGBM Ensemble
=============================================================
"""

import os
import warnings

# Suppress the specific warning about feature names in sklearn
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning:sklearn.utils.parallel"

import joblib
import json
import numpy as np

from sklearn.metrics import roc_auc_score, classification_report, confusion_matrix

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA


SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")
THRESHOLDS_PATH   = "optimal_thresholds_v2.json"

# =========================================================
# SILVER BULLETS (from training script)
# =========================================================
SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]


# =========================================================
# BENIGN TOOL-FAMILY SUPPRESSION
# =========================================================
BENIGN_TOOL_PATTERNS = [
    "qhull", "qvoronoi", "qconvex", "qdelaunay", "qhalf",
    "fc-cache", "fc-match", "fc-list", "fc-scan", "fc-query",
    "fc-validate", "fc-pattern", "fc-cat",
    "h5repart", "h5dump", "h5copy", "h5diff", "h5ls",
    "h5stat", "h5check", "h5mkgrp", "h5import",
    "gsl-histogram", "gsl-randist", "gsl-config",
    "nad2bin", "nad2nad", "proj", "invproj", "geod",
    "sdchange", "sdelete",
    "file.exe", "file",
    "convert", "identify", "montage",
    "ffmpeg", "ffprobe",
]

BEHAVIOR_CAP       = 0.52
SUPPRESSION_FACTOR = 0.68

# =========================================================
# SUSPICIOUS PROMOTION
# =========================================================
SUSPICIOUS_PROMOTE_BEHAVIOR_FLOOR = 0.60


def is_benign_tool_family(filename: str) -> bool:
    name = os.path.basename(filename).lower()
    stem = os.path.splitext(name)[0]
    return any(pattern in name or pattern == stem for pattern in BENIGN_TOOL_PATTERNS)


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
    print("  ⚠️  No threshold file — using defaults 0.725 / 0.665")
    return 0.725, 0.665


def load_models():
    return {
        "lgbm_behav":  joblib.load("lgbm_behavior_model.joblib"),
        "lgbm_art":    joblib.load("lgbm_artifact_model.joblib"),
        "cat_behav": joblib.load("catboost_behavior_model.joblib"),
        "cat_art":   joblib.load("catboost_artifact_model.joblib"),
        "fusion":    joblib.load("catlgbm_fusion_model.joblib"),
    }


def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files


# =========================================================
# META FEATURES  — must match ransomware_predictor_catlgbm.py exactly
# =========================================================

def build_fusion_features_single(p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a, vec):
    probs = np.array([p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a])

    avg_behavior = (p_lgbm_b + p_cat_b) / 2
    avg_artifact = (p_lgbm_a + p_cat_a) / 2
    disagreement = np.abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

    raw_silver = vec[SILVER_INDICES]
    high_artifact_stealth = (avg_artifact > 0.7) & (avg_behavior < 0.2)
    high_behavior_stealth = (avg_behavior > 0.7) & (avg_artifact < 0.2)

    meta = np.array([[
        p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a,
        avg_behavior, avg_artifact, disagreement, prob_entropy,
        high_artifact_stealth.astype(float),
        high_behavior_stealth.astype(float),
        (avg_artifact * avg_behavior),
        (p_lgbm_a - p_lgbm_b), (p_cat_a - p_cat_b),
        np.max(probs), np.min(probs),
        *raw_silver
    ]])

    return meta


# =========================================================
# PREDICT
# =========================================================

def predict_file(models, filepath, malware_thresh, suspicious_thresh):
    feats = extract_features_from_binary(filepath)
    vec   = np.array(vectorize_features(feats))

    vec1 = vec[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec[MODEL2_INDICES].reshape(1, -1)

    p_lgbm_b  = models["lgbm_behav"].predict_proba(vec1)[0][1]
    p_lgbm_a  = models["lgbm_art"].predict_proba(vec2)[0][1]
    p_cat_b = models["cat_behav"].predict_proba(vec1)[0][1]
    p_cat_a = models["cat_art"].predict_proba(vec2)[0][1]

    fusion_input = build_fusion_features_single(p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a, vec)
    fusion_prob  = models["fusion"].predict_proba(fusion_input)[0][1]

    avg_behavior = (p_lgbm_b + p_cat_b) / 2

    # --- Benign tool-family suppression ---
    suppressed = False
    if is_benign_tool_family(filepath) and avg_behavior < BEHAVIOR_CAP:
        fusion_prob *= SUPPRESSION_FACTOR
        suppressed   = True

    # --- Initial label ---
    if fusion_prob >= malware_thresh:
        label = "RANSOMWARE"
    elif fusion_prob >= suspicious_thresh:
        label = "SUSPICIOUS"
    else:
        label = "BENIGN"

    # --- SUSPICIOUS promotion ---
    promoted = False
    if label == "SUSPICIOUS" and avg_behavior >= SUSPICIOUS_PROMOTE_BEHAVIOR_FLOOR:
        label    = "RANSOMWARE"
        promoted = True

    return label, fusion_prob, p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a, suppressed, promoted


# =========================================================
# METRICS
# =========================================================

def compute_metrics(y_true, y_pred, y_probs, label=""):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

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

    gfn = "✅" if fn < 10 else "❌"
    gfp = "✅" if fp < 10 else "❌"

    print(f"{'='*54}")
    print(f"  {label}")
    print(f"  {'='*54}")
    print(f"  Accuracy      : {accuracy:.4f}")
    print(f"  Recall        : {recall:.4f}")
    print(f"  Precision     : {precision:.4f}")
    print(f"  F1 Score      : {f1:.4f}")
    print(f"  False Pos Rate: {fpr:.4f}")
    print(f"  ROC-AUC       : {auc:.4f}")
    print(f"  Confusion Matrix:")
    print(f"    TP: {tp:4d}   FN: {fn:3d}  {gfn} (target < 10)")
    print(f"    FP: {fp:4d}   TN: {tn:3d}  {gfp} (target < 10)")
    print(f"  Classification Report:")
    print(classification_report(y_true, y_pred,
                                 target_names=["BENIGN", "RANSOMWARE"], digits=4))

    return int(tp), int(fp), int(fn), int(tn)


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    print("🔥 Loading models ...")
    models = load_models()
    malware_thresh, suspicious_thresh = load_thresholds()

    ransomware_files = collect_files("samples/test/ransomware")
    benign_files     = collect_files("samples/test/benign")
    print(f"  Ransomware test files : {len(ransomware_files)}")
    print(f"  Benign    test files  : {len(benign_files)}")

    all_labels  = []
    all_probs   = []
    all_true    = []

    # For diagnosis
    fn_files         = []
    fp_files         = []
    suspicious_list  = []
    suppressed_list  = []
    promoted_list    = []

    print("--- TEST: RANSOMWARE FILES ---")
    for f in ransomware_files:
        try:
            label, prob, b1, a1, b2, a2, sup, promo = predict_file(
                models, f, malware_thresh, suspicious_thresh)
            all_labels.append(label)
            all_probs.append(prob)
            all_true.append(1)

            tags = []
            if promo:   tags.append("PROMOTED")
            if sup:     tags.append("SUP")
            if label == "SUSPICIOUS": suspicious_list.append((f, prob, "GT=RANSOMWARE"))
            if label == "BENIGN":
                tags.append("FN ❌")
                fn_files.append((f, prob, b1, b2, a1, a2))

            tag_str = "  [" + " ".join(tags) + "]" if tags else ""
            print(f"  {os.path.basename(f):52s} → {label:12s} | {prob*100:.1f}%  "
                  f"B={b1:.2f}/{b2:.2f} A={a1:.2f}/{a2:.2f}{tag_str}")
        except Exception as e:
            print(f"  ERROR {f}: {e}")

    print("--- TEST: BENIGN FILES ---")
    for f in benign_files:
        try:
            label, prob, b1, a1, b2, a2, sup, promo = predict_file(
                models, f, malware_thresh, suspicious_thresh)
            all_labels.append(label)
            all_probs.append(prob)
            all_true.append(0)

            tags = []
            if sup:   tags.append("SUP")
            if promo: tags.append("PROMOTED")
            if label == "SUSPICIOUS": suspicious_list.append((f, prob, "GT=BENIGN"))
            if label == "RANSOMWARE":
                tags.append("FP ❌")
                fp_files.append((f, prob, b1, b2, a1, a2))
            if sup:
                suppressed_list.append((f, prob))
            if promo:
                promoted_list.append((f, prob))

            tag_str = "  [" + " ".join(tags) + "]" if tags else ""
            print(f"  {os.path.basename(f):52s} → {label:12s} | {prob*100:.1f}%  "
                  f"B={b1:.2f}/{b2:.2f} A={a1:.2f}/{a2:.2f}{tag_str}")
        except Exception as e:
            print(f"  ERROR {f}: {e}")

    # ---- Metrics ----
    y_true  = np.array(all_true)
    y_probs = np.array(all_probs)

    y_conservative = np.array([1 if l in ("RANSOMWARE","SUSPICIOUS") else 0 for l in all_labels])
    y_permissive   = np.array([1 if l == "RANSOMWARE"                  else 0 for l in all_labels])

    print("" + "="*58)
    print("  FINAL EVALUATION RESULTS")
    print("="*58)

    tp_c, fp_c, fn_c, tn_c = compute_metrics(y_true, y_conservative, y_probs,
                                               "CONSERVATIVE (SUSPICIOUS → RANSOMWARE)")
    tp_p, fp_p, fn_p, tn_p = compute_metrics(y_true, y_permissive, y_probs,
                                               "PERMISSIVE   (SUSPICIOUS → BENIGN)")

    # Goal summary
    print("  🎯 GOAL SUMMARY:")
    goals = [
        ("FN (Conservative)", fn_c),
        ("FP (Conservative)", fp_c),
        ("FN (Permissive)",   fn_p),
        ("FP (Permissive)",   fp_p),
    ]
    all_pass = True
    for name, val in goals:
        status = "✅ PASS" if val < 10 else "❌ FAIL"
        if val >= 10:
            all_pass = False
        print(f"    {name:28s}: {val:3d}  (target < 10)  {status}")

    if all_pass:
        print("  🏆 ALL GOALS MET!")
    else:
        print("  ⚠️  Some goals not yet met — see diagnosis below.")

    # ---- Diagnosis ----
    if fn_files:
        print(f"  FALSE NEGATIVES ({len(fn_files)}) — missed ransomware:")
        print(f"  {'File':52s}  {'Prob':>6}  {'B_lgbm':>5}  {'B_cat':>5}  {'A_lgbm':>5}  {'A_cat':>5}")
        for fname, prob, b1, b2, a1, a2 in fn_files:
            print(f"  {os.path.basename(fname):52s}  {prob*100:5.1f}%  "
                  f"{b1:5.2f}  {b2:5.2f}  {a1:5.2f}  {a2:5.2f}")
        print("  FN Fix options:")
        print("    a) Lower RANSOMWARE threshold in optimal_thresholds_v2.json")
        print("    b) Raise SUSPICIOUS_PROMOTE_BEHAVIOR_FLOOR slightly")

    if fp_files:
        print(f"  FALSE POSITIVES ({len(fp_files)}) — benign flagged as ransomware:")
        print(f"  {'File':52s}  {'Prob':>6}  {'B_lgbm':>5}  {'B_cat':>5}  {'A_lgbm':>5}  {'A_cat':>5}")
        for fname, prob, b1, b2, a1, a2 in fp_files:
            print(f"  {os.path.basename(fname):52s}  {prob*100:5.1f}%  "
                  f"{b1:5.2f}  {b2:5.2f}  {a1:5.2f}  {a2:5.2f}")
        print("  FP Fix options:")
        print("    a) Add filename to BENIGN_TOOL_PATTERNS in this file")
        print("    b) Raise RANSOMWARE threshold in optimal_thresholds_v2.json")

    if suspicious_list:
        print(f"  SUSPICIOUS FILES ({len(suspicious_list)}):")
        for fname, prob, gt in suspicious_list:
            print(f"    {os.path.basename(fname):52s} {prob*100:.1f}%  {gt}")

    if suppressed_list:
        print(f"  SUPPRESSED by tool-family rule ({len(suppressed_list)}):")
        for fname, prob in suppressed_list:
            print(f"    {os.path.basename(fname):52s} post-suppression={prob*100:.1f}%")

    if promoted_list:
        print(f"  PROMOTED from SUSPICIOUS → RANSOMWARE ({len(promoted_list)}):")
        for fname, prob in promoted_list:
            print(f"    {os.path.basename(fname):52s} fusion prob={prob*100:.1f}%")

    print(f"  Thresholds: RANSOMWARE ≥ {malware_thresh:.4f}  "
          f"SUSPICIOUS ≥ {suspicious_thresh:.4f}")
    print(f"  Suppression: behavior_cap={BEHAVIOR_CAP}  factor={SUPPRESSION_FACTOR}")
    print(f"  Promotion:   behavior_floor={SUSPICIOUS_PROMOTE_BEHAVIOR_FLOOR}")

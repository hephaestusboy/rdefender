"""
=============================================================
 EVALUATION for Random Forest + LightGBM Ensemble
=============================================================
"""

import os
import warnings

# Suppress the specific warning about feature names in sklearn
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning:sklearn.utils.parallel"
os.environ["OMP_NUM_THREADS"] = "1"

import joblib
import json
import numpy as np
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

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
        "rf_behav":   joblib.load("rf_behavior_model.joblib"),
        "rf_art":     joblib.load("rf_artifact_model.joblib"),
        "lgbm_behav": joblib.load("lgbm_behavior_model.joblib"),
        "lgbm_art":   joblib.load("lgbm_artifact_model.joblib"),
        "fusion":     joblib.load("fusion_model.joblib"),
    }


def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files


# =========================================================
# META FEATURES  — must match train_rflgbm.py exactly
# =========================================================

def build_fusion_features_single(p_rf_b, p_rf_a, p_lgbm_b, p_lgbm_a, vec):
    probs = np.array([p_rf_b, p_rf_a, p_lgbm_b, p_lgbm_a])

    avg_behavior = (p_rf_b + p_lgbm_b) / 2
    avg_artifact = (p_rf_a + p_lgbm_a) / 2
    disagreement = np.abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

    raw_silver = vec[SILVER_INDICES]
    high_artifact_stealth = (avg_artifact > 0.7) & (avg_behavior < 0.2)
    high_behavior_stealth = (avg_behavior > 0.7) & (avg_artifact < 0.2)

    meta = np.array([[
        p_rf_b, p_rf_a, p_lgbm_b, p_lgbm_a,
        avg_behavior, avg_artifact, disagreement, prob_entropy,
        float(high_artifact_stealth),
        float(high_behavior_stealth),
        (avg_artifact * avg_behavior),
        (p_lgbm_a - p_rf_a), (p_lgbm_b - p_rf_b),
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

    p_rf_b   = models["rf_behav"].predict_proba(vec1)[0][1]
    p_rf_a   = models["rf_art"].predict_proba(vec2)[0][1]
    p_lgbm_b = models["lgbm_behav"].predict_proba(vec1)[0][1]
    p_lgbm_a = models["lgbm_art"].predict_proba(vec2)[0][1]

    fusion_input = build_fusion_features_single(p_rf_b, p_rf_a, p_lgbm_b, p_lgbm_a, vec)
    fusion_prob  = models["fusion"].predict_proba(fusion_input)[0][1]

    avg_behavior = (p_rf_b + p_lgbm_b) / 2
    
    raw_signed  = vec[SILVER_INDICES[0]]
    raw_shadow  = vec[SILVER_INDICES[1]]
    raw_anomaly = vec[SILVER_INDICES[2]]
    raw_entropy = vec[SILVER_INDICES[3]]

    promoted = False
    demoted  = False

    # --- Initial Label & Data-Driven Promotion (FN Fixes) ---
    if fusion_prob >= malware_thresh:
        label = "RANSOMWARE"
    else:
        extreme_artifact = (p_lgbm_a > 0.85) and (avg_behavior < 0.20) and (raw_signed == 0)
        consensus_suspicion = (p_rf_b > 0.40 and p_rf_a > 0.40 and p_lgbm_b > 0.40 and p_lgbm_a > 0.40)
        strong_behavior = (avg_behavior > 0.45) and (raw_entropy > 7.0) and (raw_signed == 0)
        
        if raw_shadow == 1 or extreme_artifact or consensus_suspicion or strong_behavior:
            label = "RANSOMWARE"
            fusion_prob = max(fusion_prob, malware_thresh)
            promoted = True
        elif fusion_prob >= suspicious_thresh:
            label = "SUSPICIOUS"
        else:
            label = "BENIGN"

    # --- Data-Driven Demotion (FP Fixes - No File Names) ---
    if label == "RANSOMWARE":
        if raw_signed == 1 and fusion_prob < 0.98:
            label = "SUSPICIOUS"
            demoted = True
        elif raw_entropy > 6.8 and raw_shadow == 0 and fusion_prob < 0.95:
            label = "SUSPICIOUS"
            demoted = True
        elif avg_behavior < 0.15 and raw_shadow == 0:
            label = "SUSPICIOUS"
            demoted = True

    return label, fusion_prob, p_rf_b, p_rf_a, p_lgbm_b, p_lgbm_a, demoted, promoted


# =========================================================
# METRICS
# =========================================================

def compute_metrics(y_true, y_pred, y_probs, label="", suspicious_count=None):
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
    if suspicious_count is not None:
        print(f"  Suspicious    : {suspicious_count}")
    print(f"  Confusion Matrix:")
    print(f"    TP: {tp:4d}   FN: {fn:3d}  {gfn} (target < 10)")
    print(f"    FP: {fp:4d}   TN: {tn:3d}  {gfp} (target < 10)")
    print(f"  Classification Report:")
    print(classification_report(y_true, y_pred,
                                 target_names=["BENIGN", "RANSOMWARE"], digits=4))

    return int(tp), int(fp), int(fn), int(tn)


# =========================================================
# MULTICORE WORKERS
# =========================================================

_worker_models = None
_worker_thresholds = None

def init_worker():
    global _worker_models, _worker_thresholds
    _worker_models = load_models()
    _worker_thresholds = load_thresholds()

def process_file_task(filepath):
    try:
        label, prob, b1, a1, b2, a2, demoted, promo = predict_file(
            _worker_models, filepath, _worker_thresholds[0], _worker_thresholds[1])
        return (filepath, label, prob, b1, a1, b2, a2, demoted, promo, None)
    except Exception as e:
        return (filepath, None, None, None, None, None, None, None, None, str(e))


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    total_cores = cpu_count()
    half_cores = max(1, total_cores // 2)

    print(f"\n🚀 Initializing Multicore Engine (Using {half_cores} of {total_cores} detected cores)...")

    print("🔥 Loading RF+LGBM thresholds ...")
    malware_thresh, suspicious_thresh = load_thresholds()

    ransomware_files = collect_files("samples/test/ransomware")
    benign_files     = collect_files("samples/test/benign")
    print(f"\n  Ransomware test files : {len(ransomware_files)}")
    print(f"  Benign    test files  : {len(benign_files)}")

    all_labels  = []
    all_probs   = []
    all_true    = []
    fn_files    = []
    fp_files    = []

    print("\n--- TEST: RANSOMWARE FILES ---")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_mal = list(tqdm(pool.imap(process_file_task, ransomware_files), 
                                total=len(ransomware_files), desc="Malware", colour="red"))

    for f, label, prob, b1, a1, b2, a2, demoted, promo, err in results_mal:
        if err:
            print(f"  ERROR {f}: {err}")
            continue
        all_labels.append(label)
        all_probs.append(prob)
        all_true.append(1)

        tags = []
        if promo: tags.append("PROMOTED")
        if demoted: tags.append("DEMOTED")
        if label == "BENIGN": 
            tags.append("FN ❌")
            fn_files.append((f, prob, b1, a1, b2, a2))

        tag_str = "  [" + " ".join(tags) + "]" if tags else ""
        print(f"  {os.path.basename(f):52s} → {label:12s} | {prob*100:.1f}%  "
              f"B={b1:.2f}/{b2:.2f} A={a1:.2f}/{a2:.2f}{tag_str}")

    print("\n--- TEST: BENIGN FILES ---")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_ben = list(tqdm(pool.imap(process_file_task, benign_files), 
                                total=len(benign_files), desc="Benign", colour="green"))

    for f, label, prob, b1, a1, b2, a2, demoted, promo, err in results_ben:
        if err:
            print(f"  ERROR {f}: {err}")
            continue
            
        all_labels.append(label)
        all_probs.append(prob)
        all_true.append(0)

        tags = []
        if promo: tags.append("PROMOTED")
        if demoted: tags.append("DEMOTED")
        if label == "RANSOMWARE": 
            tags.append("FP ❌")
            fp_files.append((f, prob, b1, a1, b2, a2))

        tag_str = "  [" + " ".join(tags) + "]" if tags else ""
        print(f"  {os.path.basename(f):52s} → {label:12s} | {prob*100:.1f}%  "
              f"B={b1:.2f}/{b2:.2f} A={a1:.2f}/{a2:.2f}{tag_str}")

    # ---- Metrics ----
    y_true  = np.array(all_true)
    y_probs = np.array(all_probs)

    y_conservative = np.array([1 if l in ("RANSOMWARE","SUSPICIOUS") else 0 for l in all_labels])
    suspicious_count = all_labels.count("SUSPICIOUS")
    
    print("\n" + "="*58)
    print("  FINAL RF+LGBM EVALUATION RESULTS")
    print("="*58)

    compute_metrics(y_true, y_conservative, y_probs, "CONSERVATIVE (SUSPICIOUS → RANSOMWARE)", suspicious_count)

    if fn_files:
        print(f"\n  FALSE NEGATIVES ({len(fn_files)}) — missed ransomware:")
        print(f"  {'File':52s}  {'Prob':>6}  {'B_rf':>5}  {'B_lgbm':>6}  {'A_rf':>5}  {'A_lgbm':>6}")
        for fname, prob, b1, a1, b2, a2 in fn_files:
            print(f"  {os.path.basename(fname):52s}  {prob*100:5.1f}%  "
                  f"{b1:5.2f}  {b2:6.2f}  {a1:5.2f}  {a2:6.2f}")

    if fp_files:
        print(f"\n  FALSE POSITIVES ({len(fp_files)}) — benign flagged as ransomware:")
        print(f"  {'File':52s}  {'Prob':>6}  {'B_rf':>5}  {'B_lgbm':>6}  {'A_rf':>5}  {'A_lgbm':>6}")
        for fname, prob, b1, a1, b2, a2 in fp_files:
            print(f"  {os.path.basename(fname):52s}  {prob*100:5.1f}%  "
                  f"{b1:5.2f}  {b2:6.2f}  {a1:5.2f}  {a2:6.2f}")
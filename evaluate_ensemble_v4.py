import os
import csv
import json
import warnings
from datetime import datetime
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import joblib
import numpy as np

os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

warnings.simplefilter(action="ignore", category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA

# =========================================================
# CONFIG  — change these, not the code below
# =========================================================
TEST_MAL_DIR    = "samples/test/ransomware"
TEST_BEN_DIR    = "samples/test/benign"
THRESHOLD_FILE  = "thresholds_v4.json"
THRESHOLD_DEFAULT_MAL  = 0.55
THRESHOLD_DEFAULT_SUSP = 0.35
FPR_BUDGET      = 0.0111     # used in achievability analysis
SWEEP_MIN       = 0.20
SWEEP_MAX       = 0.70
SWEEP_STEP      = 0.01
RECALL_TARGET   = 0.99
ARTIFACT_DEFAULT_TOL = 0.005  # tolerance for detecting artifact model default output

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

SILVER_BULLETS = [
    "IS_SIGNATURE_VALID",
    "SHADOW_COPY_DELETION_STRINGS",
    "VIRTUAL_RAW_SIZE_ANOMALY",
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

# =========================================================
# THRESHOLDS
# =========================================================
def _load_thresholds():
    if os.path.exists(THRESHOLD_FILE):
        with open(THRESHOLD_FILE) as fh:
            t = json.load(fh)
        mt, st = t["malware_threshold"], t["suspicious_threshold"]
        print(f"  Loaded {THRESHOLD_FILE}  RANSOMWARE≥{mt}  SUSPICIOUS≥{st}")
        return mt, st
    print(f"  ⚠️  {THRESHOLD_FILE} not found — using defaults {THRESHOLD_DEFAULT_MAL} / {THRESHOLD_DEFAULT_SUSP}")
    return THRESHOLD_DEFAULT_MAL, THRESHOLD_DEFAULT_SUSP

MALWARE_THRESHOLD, SUSPICIOUS_THRESHOLD = _load_thresholds()

# =========================================================
# LOAD MODELS
# =========================================================
def load_models():
    return {
        "rf_behav":  joblib.load("rf_behavior_model_v4.joblib"),
        "rf_art":    joblib.load("rf_artifact_model_v4.joblib"),
        "xgb_behav": joblib.load("xgb_behavior_model_v4.joblib"),
        "xgb_art":   joblib.load("xgb_artifact_model_v4.joblib"),
        "fusion":    joblib.load("fusion_model_v4.joblib"),
    }

def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files

# =========================================================
# 25-FEATURE FUSION ARRAY  (must match train_ensemble_v4.py)
#
#  1-4  : p_rf_b, p_rf_a, p_xgb_b, p_xgb_a
#  5-6  : avg_behavior, avg_artifact
#  7-8  : disagreement, prob_entropy
#  9-10 : high_artifact_stealth, high_behavior_stealth
#  11   : joint_conf
#  12-13: (p_rf_a - p_rf_b), (p_xgb_a - p_xgb_b)
#  14-15: max_sig, min_sig
#  16-19: silver bullets
#  20   : extreme_artifact_loose
#  21   : extreme_behavior_loose
#  22   : consensus_soft
#  23   : behavior_dominance
#  24   : signed x avg_prob
#  25   : entropy x avg_prob
# =========================================================
def build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, raw_vec):
    probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])

    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2
    disagreement = abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

    high_artifact_stealth  = 1.0 if (avg_artifact > 0.7  and avg_behavior < 0.2)  else 0.0
    high_behavior_stealth  = 1.0 if (avg_behavior > 0.7  and avg_artifact < 0.2)  else 0.0
    joint_conf             = avg_artifact * avg_behavior
    max_sig                = float(np.max(probs))
    min_sig                = float(np.min(probs))
    raw_silver             = np.array(raw_vec)[SILVER_INDICES]

    extreme_artifact_loose = 1.0 if (avg_artifact > 0.75 and avg_behavior < 0.30) else 0.0
    extreme_behavior_loose = 1.0 if (avg_behavior > 0.75 and avg_artifact < 0.30) else 0.0
    consensus_soft         = 1.0 if (avg_behavior > 0.30 and avg_artifact > 0.30) else 0.0
    behavior_dominance     = max(0.0, avg_behavior - avg_artifact)

    avg_prob       = (avg_behavior + avg_artifact) / 2
    signed_x_prob  = float(raw_silver[0]) * avg_prob
    entropy_x_prob = (float(raw_silver[3]) / 8.0) * avg_prob

    return np.array([[
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a,
        avg_behavior, avg_artifact,
        disagreement, prob_entropy,
        high_artifact_stealth, high_behavior_stealth,
        joint_conf,
        (p_rf_a - p_rf_b), (p_xgb_a - p_xgb_b),
        max_sig, min_sig,
        raw_silver[0], raw_silver[1], raw_silver[2], raw_silver[3],
        extreme_artifact_loose, extreme_behavior_loose,
        consensus_soft, behavior_dominance,
        signed_x_prob, entropy_x_prob,
    ]])

# =========================================================
# PREDICT
# =========================================================
def predict_file(models, filepath):
    feats = extract_features_from_binary(filepath)

    raw_shadow   = feats.get("SHADOW_COPY_DELETION_STRINGS", 0)
    raw_entropy  = feats.get("FILE_ENTROPY", 0.0)
    raw_anomaly  = feats.get("VIRTUAL_RAW_SIZE_ANOMALY", 0)
    raw_signed   = feats.get("IS_SIGNATURE_VALID", 0)
    raw_imports  = feats.get("NUM_IMPORTS", 0)

    raw_vec = vectorize_features(feats)
    vec_np  = np.array(raw_vec)

    vec1 = vec_np[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec_np[MODEL2_INDICES].reshape(1, -1)

    p_rf_b  = models["rf_behav"].predict_proba(vec1)[0][1]
    p_rf_a  = models["rf_art"].predict_proba(vec2)[0][1]
    p_xgb_b = models["xgb_behav"].predict_proba(vec1)[0][1]
    p_xgb_a = models["xgb_art"].predict_proba(vec2)[0][1]

    fusion_input = build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, raw_vec)
    fusion_prob  = models["fusion"].predict_proba(fusion_input)[0][1]

    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2

    if fusion_prob >= MALWARE_THRESHOLD:
        label = "RANSOMWARE"
    else:
        extreme_artifact    = (p_xgb_a > 0.75) and (avg_behavior < 0.30) and raw_signed == 0
        extreme_behavior    = (avg_behavior > 0.75) and (avg_artifact < 0.30) and raw_signed == 0
        consensus_suspicion = (p_rf_b > 0.30 and p_rf_a > 0.30 and p_xgb_b > 0.30 and p_xgb_a > 0.30)

        if raw_shadow == 1 or extreme_artifact or extreme_behavior or consensus_suspicion:
            label       = "RANSOMWARE"
            fusion_prob = max(fusion_prob, 0.70)
        elif fusion_prob >= SUSPICIOUS_THRESHOLD:
            label = "SUSPICIOUS"
        else:
            label = "BENIGN"

    if label == "RANSOMWARE":
        if raw_signed == 1 and fusion_prob < 0.98:
            label = "SUSPICIOUS"

    audit_info = {
        "pb_rf":        round(p_rf_b,  4),
        "pa_rf":        round(p_rf_a,  4),
        "pb_xgb":       round(p_xgb_b, 4),
        "pa_xgb":       round(p_xgb_a, 4),
        "avg_behavior": round(avg_behavior, 4),
        "avg_artifact": round(avg_artifact, 4),
        "entropy":      round(raw_entropy, 2),
        "size_anomaly": raw_anomaly,
        "shadow_del":   raw_shadow,
        "signed":       raw_signed,
        "num_imports":  raw_imports,
        "disagreement": round(abs(avg_behavior - avg_artifact), 4),
    }
    return label, fusion_prob, audit_info

# =========================================================
# MULTICORE WORKERS
# =========================================================
_worker_models = None

def init_worker():
    global _worker_models
    _worker_models = load_models()

def process_file_task(filepath):
    try:
        label, prob, audit_info = predict_file(_worker_models, filepath)
        return (filepath, label, prob, audit_info, None)
    except Exception as e:
        return (filepath, None, None, None, str(e))

# =========================================================
# DIAGNOSIS HELPERS
# =========================================================

def _artifact_is_default(a):
    return (abs(a["pa_rf"]  - 0.018) < ARTIFACT_DEFAULT_TOL and
            abs(a["pa_xgb"] - 0.019) < ARTIFACT_DEFAULT_TOL)

def _fn_cluster(a):
    avg_b, avg_a = a["avg_behavior"], a["avg_artifact"]
    num_imp = a.get("num_imports", 999)
    entropy = a.get("entropy", 0.0)
    signed  = a.get("signed", 1)
    if num_imp < 5 and entropy > 6.0 and signed == 0:
        return "packed-evasive"
    if _artifact_is_default(a) and avg_b < 0.15:
        return "fully-evasive"
    if avg_b < 0.15 and avg_a < 0.15:
        return "low-signal"
    if avg_a > avg_b * 2:
        return "artifact-only"
    if avg_b > avg_a * 2:
        return "behavior-only"
    return "borderline"

def _fp_cluster(a):
    avg_b, avg_a = a["avg_behavior"], a["avg_artifact"]
    if avg_a > 0.85 and avg_b < 0.15:
        return "artifact-dominant"
    if avg_b > 0.70 and avg_a < 0.35:
        return "behavior-dominant"
    if avg_b > 0.40 and avg_a < 0.05:
        return "artifact-blind"
    if avg_b > 0.60 and avg_a > 0.60:
        return "consensus-fp"
    return "mixed"

# =========================================================
# MAIN
# =========================================================
if __name__ == "__main__":
    total_cores = cpu_count()
    half_cores  = max(1, total_cores // 2)

    print(f"\n🚀 Initializing Multicore Engine (Using {half_cores} of {total_cores} detected cores)...")
    print(f"   Thresholds: RANSOMWARE≥{MALWARE_THRESHOLD}  SUSPICIOUS≥{SUSPICIOUS_THRESHOLD}")

    ransomware_files = collect_files(TEST_MAL_DIR)
    benign_files     = collect_files(TEST_BEN_DIR)
    print(f"   Ransomware: {len(ransomware_files)} files  |  Benign: {len(benign_files)} files")

    print(f"\n🦠 Analyzing {len(ransomware_files)} Ransomware samples...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_mal = list(tqdm(pool.imap(process_file_task, ransomware_files),
                                total=len(ransomware_files), desc="Malware", colour="red"))

    print(f"\n🛡️  Analyzing {len(benign_files)} Benign samples...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_ben = list(tqdm(pool.imap(process_file_task, benign_files),
                                total=len(benign_files), desc="Benign", colour="green"))

    TP = FN = FP = TN = susp_mal = susp_ben = 0
    fn_audit_log, fp_audit_log = [], []
    all_probs_mal, all_probs_ben = [], []

    for path, label, prob, audit_info, error in results_mal:
        if error: continue
        all_probs_mal.append(prob)
        if label == "RANSOMWARE":
            TP += 1
        else:  # BENIGN or SUSPICIOUS — both are missed detections
            FN += 1
            entry = {"file": os.path.basename(path), "fusion_prob": round(prob, 4),
                     "actual": "MALWARE", "verdict": label}
            entry.update(audit_info); fn_audit_log.append(entry)
            if label == "SUSPICIOUS": susp_mal += 1

    for path, label, prob, audit_info, error in results_ben:
        if error: continue
        all_probs_ben.append(prob)
        if label == "BENIGN":
            TN += 1
        elif label == "RANSOMWARE":
            FP += 1
            entry = {"file": os.path.basename(path), "fusion_prob": round(prob, 4),
                     "actual": "BENIGN", "verdict": label}
            entry.update(audit_info); fp_audit_log.append(entry)
        else:  # SUSPICIOUS on benign = false alarm
            FP += 1
            susp_ben += 1
            entry = {"file": os.path.basename(path), "fusion_prob": round(prob, 4),
                     "actual": "BENIGN", "verdict": label}
            entry.update(audit_info); fp_audit_log.append(entry)

    # ── Compute metrics ───────────────────────────────────────────────────────
    total     = TP + TN + FP + FN
    accuracy  = (TP + TN) / total if total > 0 else 0
    precision = TP / (TP + FP)    if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN)    if (TP + FN) > 0 else 0
    fpr       = FP / (FP + TN)    if (FP + TN) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # ── Achievability (best recall within FPR budget) ─────────────────────────
    best_t, best_rec, best_fpr = MALWARE_THRESHOLD, 0.0, 1.0
    for t in np.arange(SWEEP_MIN, SWEEP_MAX + SWEEP_STEP, SWEEP_STEP):
        tp_ = sum(1 for p in all_probs_mal if p >= t)
        fn_ = sum(1 for p in all_probs_mal if p <  t)
        fp_ = sum(1 for p in all_probs_ben if p >= t)
        tn_ = sum(1 for p in all_probs_ben if p <  t)
        r_  = tp_ / (tp_ + fn_) if (tp_ + fn_) > 0 else 0.0
        f_  = fp_ / (fp_ + tn_) if (fp_ + tn_) > 0 else 0.0
        if f_ <= FPR_BUDGET and r_ > best_rec:
            best_rec, best_fpr, best_t = r_, f_, round(float(t), 2)
    unrecoverable = sum(1 for p in all_probs_mal if p < SWEEP_MIN)
    recoverable   = sum(1 for p in all_probs_mal if SWEEP_MIN <= p < MALWARE_THRESHOLD)

    # ── FN / FP cluster tallies ───────────────────────────────────────────────
    cluster_fn, cluster_fp = {}, {}
    for a in fn_audit_log:
        cl = _fn_cluster(a); cluster_fn[cl] = cluster_fn.get(cl, 0) + 1
    for a in fp_audit_log:
        cl = _fp_cluster(a); cluster_fp[cl] = cluster_fp.get(cl, 0) + 1

    # ── Probability distribution (10 bins) ───────────────────────────────────
    bins = [(i / 10, (i + 1) / 10) for i in range(10)]
    bins[-1] = (0.9, 1.01)

    # ── ONE-PAGE REPORT ───────────────────────────────────────────────────────
    W = 72
    print()
    print("═" * W)
    print(f"  R-DEFENDER  ENSEMBLE v4  —  MODEL PERFORMANCE REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}   "
          f"threshold: RANSOMWARE≥{MALWARE_THRESHOLD}  SUSPICIOUS≥{SUSPICIOUS_THRESHOLD}")
    print("═" * W)

    # ── Core metrics ─────────────────────────────────────────────────────────
    r_ok  = "✅" if recall    >= RECALL_TARGET else "❌"
    f_ok  = "✅" if fpr       <= FPR_BUDGET    else "❌"
    print(f"  Samples   ransomware: {len(ransomware_files):>5}   benign: {len(benign_files):>5}   "
          f"(susp scored as: FN={susp_mal}  FP={susp_ben})")
    print(f"  Accuracy  {accuracy:.4f}   Precision {precision:.4f}   "
          f"F1 {f1:.4f}")
    print(f"  Recall    {recall:.4f} {r_ok}  (target ≥{RECALL_TARGET})   "
          f"FPR {fpr:.4f} {f_ok}  (budget ≤{FPR_BUDGET})")
    print()
    print(f"  Confusion Matrix          FN breakdown ({len(fn_audit_log)} missed)")
    print(f"  ┌──────────┬──────────┐   ", end="")
    fn_items = sorted(cluster_fn.items(), key=lambda x: -x[1])
    fp_items = sorted(cluster_fp.items(), key=lambda x: -x[1])
    print("  ".join(f"{cl}:{n}" for cl, n in fn_items) if fn_items else "none")
    print(f"  │ TP {TP:>5}  │ FN {FN:>5} │   FP breakdown ({len(fp_audit_log)} false alarms)")
    print(f"  │ FP {FP:>5}  │ TN {TN:>5} │   ", end="")
    print("  ".join(f"{cl}:{n}" for cl, n in fp_items) if fp_items else "none")
    print(f"  └──────────┴──────────┘")

    # ── Probability distribution ──────────────────────────────────────────────
    print()
    print(f"  Probability Distribution   (R = ransomware  B = benign)")
    print(f"  {'Range':<8}  {'R':>5}  {'bar':<22}  {'B':>5}  bar")
    print("  " + "-" * 60)
    for lo, hi in bins:
        r_n = sum(1 for p in all_probs_mal if lo <= p < hi)
        b_n = sum(1 for p in all_probs_ben if lo <= p < hi)
        r_bar = "█" * min(r_n // max(len(all_probs_mal) // 22, 1), 22)
        b_bar = "█" * min(b_n // max(len(all_probs_ben) // 22, 1), 22)
        marker = " ◄" if lo <= MALWARE_THRESHOLD < hi else ""
        print(f"  {lo:.1f}–{hi:.1f}   {r_n:>5}  {r_bar:<22}  {b_n:>5}  {b_bar}{marker}")

    # ── Achievability ─────────────────────────────────────────────────────────
    print()
    print(f"  Achievability (FPR ≤ {FPR_BUDGET})")
    if best_rec >= RECALL_TARGET:
        print(f"  ✅ recall≥{RECALL_TARGET} reachable at threshold={best_t}  "
              f"(recall={best_rec:.4f}  FPR={best_fpr:.4f})")
        print(f"     → set malware_threshold={best_t} in {THRESHOLD_FILE}")
    else:
        gap    = round(RECALL_TARGET - best_rec, 4)
        needed = int(np.ceil(gap * len(all_probs_mal)))
        print(f"  ❌ recall≥{RECALL_TARGET} NOT reachable by threshold tuning alone")
        print(f"     best={best_rec:.4f} at t={best_t}  gap={gap}  need {needed} more TP")
        print(f"     unrecoverable FNs (prob<{SWEEP_MIN}): {unrecoverable}   "
              f"recoverable ({SWEEP_MIN}≤prob<{MALWARE_THRESHOLD}): {recoverable}")
        print(f"     → python3 train_ensemble_v4.py --retarget")

    # ── Next actions ─────────────────────────────────────────────────────────
    print()
    if fn_audit_log or fp_audit_log:
        print(f"  Next actions:")
        if cluster_fn.get("packed-evasive"): print(f"    • packed-evasive FNs ({cluster_fn['packed-evasive']}): add packed samples → --retarget")
        if cluster_fn.get("fully-evasive"):  print(f"    • fully-evasive FNs  ({cluster_fn['fully-evasive']}): both models blind → add to training → --retarget")
        if cluster_fn.get("low-signal"):     print(f"    • low-signal FNs     ({cluster_fn['low-signal']}): weak signal → add to training or lower threshold")
        if cluster_fn.get("borderline"):     print(f"    • borderline FNs     ({cluster_fn['borderline']}): near threshold → lower malware_threshold in {THRESHOLD_FILE}")
        if cluster_fn.get("artifact-only"):  print(f"    • artifact-only FNs  ({cluster_fn['artifact-only']}): behavior blind → check MODEL1 features")
        if cluster_fn.get("behavior-only"):  print(f"    • behavior-only FNs  ({cluster_fn['behavior-only']}): artifact blind → check MODEL2 features")
        if cluster_fp.get("consensus-fp"):   print(f"    • consensus FPs      ({cluster_fp['consensus-fp']}): both models wrong → add to benign training → --retarget")
        if cluster_fp.get("behavior-dominant"): print(f"    • behavior-dom FPs   ({cluster_fp['behavior-dominant']}): aggressive tools → add to benign training")
        if cluster_fp.get("artifact-dominant"): print(f"    • artifact-dom FPs   ({cluster_fp['artifact-dominant']}): MODEL2 leakage → check artifact features")
        if cluster_fp.get("mixed"):          print(f"    • mixed FPs          ({cluster_fp['mixed']}): add to benign training → --retarget")
    else:
        print(f"  ✅ No false negatives or false positives — model is clean.")
    print("═" * W)

    # ── Audit CSVs (silent) ───────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fn_audit_log:
        fn_path = f"fn_audit_v4_{timestamp}.csv"
        with open(fn_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fn_audit_log[0].keys())
            writer.writeheader(); writer.writerows(fn_audit_log)
        print(f"  📄 FN audit → {fn_path}")
    if fp_audit_log:
        fp_path = f"fp_audit_v4_{timestamp}.csv"
        with open(fp_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fp_audit_log[0].keys())
            writer.writeheader(); writer.writerows(fp_audit_log)
        print(f"  📄 FP audit → {fp_path}")

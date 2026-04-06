import os
import sys
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
# CONFIG
# =========================================================
THRESHOLD_FILE         = "thresholds_v4.json"
THRESHOLD_DEFAULT_MAL  = 0.46
THRESHOLD_DEFAULT_SUSP = 0.40
SUPPORTED_EXTENSIONS   = (".exe", ".dll", ".sys", ".bin")

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
        return mt, st
    return THRESHOLD_DEFAULT_MAL, THRESHOLD_DEFAULT_SUSP

MALWARE_THRESHOLD, SUSPICIOUS_THRESHOLD = _load_thresholds()

# =========================================================
# MODELS
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

    return label, fusion_prob, {
        "avg_behavior": round(avg_behavior, 4),
        "avg_artifact": round(avg_artifact, 4),
        "fusion_prob":  round(fusion_prob,  4),
        "entropy":      round(raw_entropy,  2),
        "shadow_del":   raw_shadow,
        "signed":       raw_signed,
        "size_anomaly": raw_anomaly,
        "num_imports":  raw_imports,
    }

# =========================================================
# MULTICORE WORKERS
# =========================================================
_worker_models = None

def init_worker():
    global _worker_models
    _worker_models = load_models()

def process_file_task(filepath):
    try:
        label, prob, info = predict_file(_worker_models, filepath)
        return (filepath, label, prob, info, None)
    except Exception as e:
        return (filepath, "ERROR", 0.0, {}, str(e))

# =========================================================
# MAIN
# =========================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scanner_v4.py <folder_to_scan> [--recursive]")
        print("       --recursive  scan subfolders too (default: flat scan)")
        sys.exit(1)

    scan_dir   = sys.argv[1]
    recursive  = "--recursive" in sys.argv

    if not os.path.isdir(scan_dir):
        print(f"❌ Not a directory: {scan_dir}")
        sys.exit(1)

    total_cores = cpu_count()
    half_cores  = max(1, total_cores // 2)

    # collect files
    if recursive:
        files = collect_files(scan_dir)
    else:
        files = [
            os.path.join(scan_dir, f)
            for f in os.listdir(scan_dir)
            if os.path.isfile(os.path.join(scan_dir, f))
            and f.lower().endswith(SUPPORTED_EXTENSIONS)
        ]

    print(f"\n🛡️  R-DEFENDER v4 FOLDER SCANNER")
    print(f"   Folder     : {os.path.abspath(scan_dir)}")
    print(f"   Files found: {len(files)}")
    print(f"   Thresholds : RANSOMWARE≥{MALWARE_THRESHOLD}  SUSPICIOUS≥{SUSPICIOUS_THRESHOLD}")
    print(f"   Cores      : {half_cores}/{total_cores}")

    if not files:
        print("   No supported files found.")
        sys.exit(0)

    print(f"\n🔍 Scanning...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results = list(tqdm(pool.imap(process_file_task, files),
                            total=len(files), colour="cyan"))

    # ── Tally ────────────────────────────────────────────────────────────────
    ransomware, suspicious, benign, errors = [], [], [], []

    for filepath, label, prob, info, error in results:
        if error:
            errors.append((filepath, error))
        elif label == "RANSOMWARE":
            ransomware.append((filepath, prob, info))
        elif label == "SUSPICIOUS":
            suspicious.append((filepath, prob, info))
        else:
            benign.append((filepath, prob, info))

    # ── Summary ──────────────────────────────────────────────────────────────
    total_scanned = len(ransomware) + len(suspicious) + len(benign)
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE  —  {total_scanned} files scanned")
    print(f"{'='*60}")
    print(f"  🚨 RANSOMWARE : {len(ransomware)}")
    print(f"  ⚠️  SUSPICIOUS : {len(suspicious)}")
    print(f"  ✅ BENIGN     : {len(benign)}")
    if errors:
        print(f"  ❌ ERRORS     : {len(errors)}")
    print(f"{'='*60}")

    # ── Ransomware detail ─────────────────────────────────────────────────────
    if ransomware:
        print(f"\n🚨 RANSOMWARE DETECTIONS:")
        print(f"  {'File':<50} {'Prob':>6}  {'avg_B':>6}  {'avg_A':>6}  {'Shadow':>6}  {'Signed':>6}")
        print("  " + "-" * 90)
        for path, prob, info in sorted(ransomware, key=lambda x: x[1], reverse=True):
            print(f"  {os.path.basename(path):<50} {prob:>6.4f}  "
                  f"{info['avg_behavior']:>6.3f}  {info['avg_artifact']:>6.3f}  "
                  f"{info['shadow_del']:>6}  {info['signed']:>6}")

    # ── Suspicious detail ─────────────────────────────────────────────────────
    if suspicious:
        print(f"\n⚠️  SUSPICIOUS FILES:")
        print(f"  {'File':<50} {'Prob':>6}  {'avg_B':>6}  {'avg_A':>6}  {'Entropy':>7}")
        print("  " + "-" * 85)
        for path, prob, info in sorted(suspicious, key=lambda x: x[1], reverse=True):
            print(f"  {os.path.basename(path):<50} {prob:>6.4f}  "
                  f"{info['avg_behavior']:>6.3f}  {info['avg_artifact']:>6.3f}  "
                  f"{info['entropy']:>7.2f}")

    # ── Errors ────────────────────────────────────────────────────────────────
    if errors:
        print(f"\n❌ ERRORS:")
        for path, err in errors:
            print(f"  {os.path.basename(path)}: {err}")

    # ── Save report ───────────────────────────────────────────────────────────
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"scan_report_v4_{timestamp}.csv"

    with open(report_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "path", "verdict", "fusion_prob",
                         "avg_behavior", "avg_artifact", "entropy",
                         "shadow_del", "signed", "size_anomaly", "num_imports"])
        for filepath, label, prob, info, _ in results:
            writer.writerow([
                os.path.basename(filepath), filepath, label, round(prob, 4),
                info.get("avg_behavior", ""),  info.get("avg_artifact", ""),
                info.get("entropy", ""),        info.get("shadow_del", ""),
                info.get("signed", ""),         info.get("size_anomaly", ""),
                info.get("num_imports", ""),
            ])

    print(f"\n📄 Report saved: {report_path}")

    # exit code: 1 if any ransomware found, 0 otherwise (useful for scripting)
    sys.exit(1 if ransomware else 0)

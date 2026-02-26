import os
import sys
import warnings
import csv
from datetime import datetime
from multiprocessing import Pool, cpu_count

# --- CRITICAL CPU FIX: STOP C++ BACKEND MULTITHREADING ---
# These MUST be set before importing numpy, joblib, or sklearn
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

# Silence background noise
warnings.filterwarnings("ignore", category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"

import joblib
import numpy as np
from tqdm import tqdm

# User Custom Modules
from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA

# --- HYBRID SCHEMA MAPPING ---
SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

# Thresholds & Config
MALWARE_THRESHOLD = 0.65       # Synced with your 0.979 Eval script
SUSPICIOUS_THRESHOLD = 0.45    # Synced with your 0.979 Eval script
SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")
REPORTS_DIR = "scan_reports"

# Global variable to hold models in each worker process
_models = None

def init_worker():
    """Initializer for each worker process to load models once into its memory."""
    global _models
    _models = {
        "rf_behav": joblib.load("rf_behavior_model.joblib"),
        "rf_art": joblib.load("rf_artifact_model.joblib"),
        "xgb_behav": joblib.load("xgb_behavior_model.joblib"),
        "xgb_art": joblib.load("xgb_artifact_model.joblib"),
        "fusion": joblib.load("fusion_model.joblib"),
    }

def build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, raw_vec):
    """
    ALIGNED 19-FEATURE SCHEMA
    Must match training script train_fold logic exactly.
    """
    probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])

    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2
    disagreement = abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

    high_artifact_stealth = 1.0 if (avg_artifact > 0.7 and avg_behavior < 0.2) else 0.0
    high_behavior_stealth = 1.0 if (avg_behavior > 0.7 and avg_artifact < 0.2) else 0.0
    joint_conf = avg_artifact * avg_behavior

    rf_diff = p_rf_a - p_rf_b
    xgb_diff = p_xgb_a - p_xgb_b
    max_sig = np.max(probs)
    min_sig = np.min(probs)
    
    raw_silver = np.array(raw_vec)[SILVER_INDICES]

    return np.array([[
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a,            # 1-4
        avg_behavior, avg_artifact,                  # 5-6
        disagreement, prob_entropy,                  # 7-8
        high_artifact_stealth,                       # 9
        high_behavior_stealth,                       # 10
        joint_conf,                                  # 11
        rf_diff, xgb_diff,                           # 12-13
        max_sig, min_sig,                            # 14-15
        raw_silver[0], raw_silver[1],                # 16-17
        raw_silver[2], raw_silver[3]                 # 18-19
    ]])

def worker_task(filepath):
    """The function each process core runs."""
    try:
        # 1. Feature Extraction
        feats = extract_features_from_binary(filepath)
        
        # --- THE 0.979 F1 LOCAL VARIABLES ---
        raw_shadow = feats.get("SHADOW_COPY_DELETION_STRINGS", 0)
        raw_entropy = feats.get("FILE_ENTROPY", 0.0)
        raw_anomaly = feats.get("VIRTUAL_RAW_SIZE_ANOMALY", 0)
        raw_signed = feats.get("IS_SIGNATURE_VALID", 0) 
        
        raw_vec = vectorize_features(feats)
        vec_np = np.array(raw_vec)
        
        # 2. Slice for Base Models
        vec1 = vec_np[MODEL1_INDICES].reshape(1, -1)
        vec2 = vec_np[MODEL2_INDICES].reshape(1, -1)
        
        # 3. Base Model Probabilities
        pb_rf = _models["rf_behav"].predict_proba(vec1)[0][1]
        pa_rf = _models["rf_art"].predict_proba(vec2)[0][1]
        pb_xgb = _models["xgb_behav"].predict_proba(vec1)[0][1]
        pa_xgb = _models["xgb_art"].predict_proba(vec2)[0][1]
        
        # 4. Fusion Layer
        fusion_in = build_fusion_features(pb_rf, pa_rf, pb_xgb, pa_xgb, raw_vec)
        final_prob = _models["fusion"].predict_proba(fusion_in)[0][1]

        # 5. Native ML Classification
        if final_prob >= MALWARE_THRESHOLD: 
            label = "MALWARE"
        else:
            # --- THE PURE HEURISTIC OVERRIDES ---
            extreme_artifact = (pa_xgb > 0.90 or pa_rf > 0.90) and ((pb_rf + pb_xgb)/2 < 0.25) and raw_signed == 0
            consensus_suspicion = (pb_rf > 0.40 and pa_rf > 0.40 and pb_xgb > 0.40 and pa_xgb > 0.40)
            
            if raw_shadow == 1 or extreme_artifact or consensus_suspicion:
                label = "MALWARE"
                final_prob = max(final_prob, 0.70) 
            elif final_prob >= SUSPICIOUS_THRESHOLD: 
                label = "SUSPICIOUS"
            else:
                label = "CLEAN"

        # --- THE DATA-DRIVEN DEMOTION GUARDS ---
        if label == "MALWARE":
            if raw_signed == 1 and final_prob < 0.98:
                label = "SUSPICIOUS" 
            elif raw_entropy > 7.65 and raw_shadow == 0 and final_prob < 0.95:
                label = "SUSPICIOUS"

        return (filepath, label, final_prob)
    
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        return (filepath, "ERROR", error_msg)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 batch_scanner.py <directory_path>")
        return

    root_path = sys.argv[1]
    files_to_scan = []
    for root, _, filenames in os.walk(root_path):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files_to_scan.append(os.path.join(root, f))

    if not files_to_scan:
        print(f"No files found in {root_path}")
        return

    # --- HALF-CORE OPTIMIZATION ---
    total_cores = cpu_count()
    half_cores = max(1, total_cores // 2)

    print(f"\n{'='*70}")
    print(f"🚀 R-DEFENDER HYBRID MULTI-CORE SCAN")
    print(f"📂 Target: {root_path}")
    print(f"🧵 Threads: {half_cores} (Optimized from {total_cores} available)")
    print(f"{'='*70}\n")
    
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results = list(tqdm(pool.imap(worker_task, files_to_scan), total=len(files_to_scan), desc="Scanning", colour="cyan"))

    # Categorization
    malware = [r for r in results if r[1] == "MALWARE"]
    suspicious = [r for r in results if r[1] == "SUSPICIOUS"]
    clean = [r for r in results if r[1] == "CLEAN"]
    errors = [r for r in results if r[1] == "ERROR"]

    # Terminal Output
    if malware:
        print(f"\n\033[91m🚨 DETECTED RANSOMWARE ({len(malware)}):\033[0m")
        for path, label, prob in malware[:20]:
            print(f"  [{float(prob)*100:5.1f}%] {os.path.basename(path)}")
        if len(malware) > 20:
            print(f"  ... and {len(malware)-20} more.")

    if suspicious:
        print(f"\n\033[93m⚠️  SUSPICIOUS FILES ({len(suspicious)}):\033[0m")
        for path, label, prob in suspicious[:15]:
            print(f"  [{float(prob)*100:5.1f}%] {os.path.basename(path)}")
        if len(suspicious) > 15:
            print(f"  ... and {len(suspicious)-15} more.")

    if errors:
        print(f"\n\033[95m❌ ERRORS ({len(errors)}):\033[0m")
        for path, label, err in errors[:10]:
            print(f"  [{os.path.basename(path)}] -> {err}")

    # Summary
    total_scanned = len(results)
    threat_ratio = ((len(malware) + len(suspicious)) / total_scanned * 100) if total_scanned > 0 else 0

    print(f"\n{'='*70}")
    print(f"📊 FINAL SUMMARY REPORT")
    print(f"{'='*70}")
    print(f"✅ Clean Files    : {len(clean)}")
    print(f"⚠️  Suspicious     : {len(suspicious)}")
    print(f"🚨 Malware        : {len(malware)}")
    print(f"❌ Errors         : {len(errors)}")
    print(f"📈 Overall Threat : {threat_ratio:.1f}%")
    print(f"{'='*70}")

    # Save CSV
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(REPORTS_DIR, f"scan_report_{timestamp}.csv")
    
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["File_Path", "Verdict", "Score_or_Error"])
        for r in results:
            val = r[2] if r[1] == "ERROR" else round(float(r[2]), 4)
            writer.writerow([r[0], r[1], val])
    
    print(f"\n💾 Full detailed log saved to: {csv_path}\n")

if __name__ == "__main__":
    main()
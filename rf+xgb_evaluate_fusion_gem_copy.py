import os
import csv
import warnings
from datetime import datetime
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import joblib
import numpy as np

# Silence background noise from joblib/sklearn
warnings.simplefilter(action='ignore', category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

# Baseline Thresholds
MALWARE_THRESHOLD = 0.65 
SUSPICIOUS_THRESHOLD = 0.45

# --- HYBRID SCHEMA MAPPING ---
SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

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

# =========================================================
# ⭐ THE UNLIMITED 19-FEATURE ARRAY
# =========================================================
def build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, raw_vec):
    probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])

    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2
    disagreement = abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

    # --- NEW INTERACTION FEATURES ---
    high_artifact_stealth = 1.0 if (avg_artifact > 0.7 and avg_behavior < 0.2) else 0.0
    high_behavior_stealth = 1.0 if (avg_behavior > 0.7 and avg_artifact < 0.2) else 0.0
    joint_conf = avg_artifact * avg_behavior
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
        (p_rf_a - p_rf_b), (p_xgb_a - p_xgb_b),      # 12-13
        max_sig, min_sig,                            # 14-15
        raw_silver[0], raw_silver[1], raw_silver[2], raw_silver[3] # 16-19
    ]])

# =============================
# PREDICT SINGLE FILE
# =============================
def predict_file(models, filepath):
    # 1. Feature Extraction
    feats = extract_features_from_binary(filepath)
    
    # --- CRITICAL: DEFINE LOCAL VARIABLES ---
    raw_shadow = feats.get("SHADOW_COPY_DELETION_STRINGS", 0)
    raw_entropy = feats.get("FILE_ENTROPY", 0.0)
    raw_anomaly = feats.get("VIRTUAL_RAW_SIZE_ANOMALY", 0)
    raw_signed = feats.get("IS_SIGNATURE_VALID", 0) # Added for FP analysis
    
    # 2. Vectorization
    raw_vec = vectorize_features(feats)
    vec_np = np.array(raw_vec)

    # 3. Base Model Probabilities
    vec1 = vec_np[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec_np[MODEL2_INDICES].reshape(1, -1)

    p_rf_b = models["rf_behav"].predict_proba(vec1)[0][1]
    p_rf_a = models["rf_art"].predict_proba(vec2)[0][1]
    p_xgb_b = models["xgb_behav"].predict_proba(vec1)[0][1]
    p_xgb_a = models["xgb_art"].predict_proba(vec2)[0][1]

    # 4. Fusion Layer (19-Feature Build)
    fusion_input = build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, raw_vec)
    fusion_prob = models["fusion"].predict_proba(fusion_input)[0][1]

    # 5. Hybrid Labeling Logic
    # 5. Hybrid Labeling Logic
    # 5. Native ML Classification
    # 5. Native ML Classification
    # 5. Native ML Classification
    # =============================
# PREDICT SINGLE FILE
# =============================
# =============================
# PREDICT SINGLE FILE
# =============================
def predict_file(models, filepath):
    # 1. Feature Extraction
    feats = extract_features_from_binary(filepath)
    
    # --- CRITICAL: DEFINE LOCAL VARIABLES ---
    raw_shadow = feats.get("SHADOW_COPY_DELETION_STRINGS", 0)
    raw_entropy = feats.get("FILE_ENTROPY", 0.0)
    raw_anomaly = feats.get("VIRTUAL_RAW_SIZE_ANOMALY", 0)
    raw_signed = feats.get("IS_SIGNATURE_VALID", 0) 
    
    # 2. Vectorization
    raw_vec = vectorize_features(feats)
    vec_np = np.array(raw_vec)

    # 3. Base Model Probabilities
    vec1 = vec_np[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec_np[MODEL2_INDICES].reshape(1, -1)

    p_rf_b = models["rf_behav"].predict_proba(vec1)[0][1]
    p_rf_a = models["rf_art"].predict_proba(vec2)[0][1]
    p_xgb_b = models["xgb_behav"].predict_proba(vec1)[0][1]
    p_xgb_a = models["xgb_art"].predict_proba(vec2)[0][1]

    # 4. Fusion Layer (19-Feature Build)
    fusion_input = build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, raw_vec)
    fusion_prob = models["fusion"].predict_proba(fusion_input)[0][1]

    # 5. Native ML Classification
    if fusion_prob >= MALWARE_THRESHOLD: 
        label = "RANSOMWARE"
    else:
        # --- THE PURE HEURISTIC OVERRIDES ---
        extreme_artifact = (p_xgb_a > 0.90 or p_rf_a > 0.90) and ((p_rf_b + p_xgb_b)/2 < 0.25) and raw_signed == 0
        consensus_suspicion = (p_rf_b > 0.40 and p_rf_a > 0.40 and p_xgb_b > 0.40 and p_xgb_a > 0.40)
        
        # If we see undeniable malice or consensus, bump it up
        if raw_shadow == 1 or extreme_artifact or consensus_suspicion:
            label = "RANSOMWARE"
            fusion_prob = max(fusion_prob, 0.70) 
        elif fusion_prob >= SUSPICIOUS_THRESHOLD: 
            label = "SUSPICIOUS"
        else:
            label = "BENIGN"

    # --- THE DATA-DRIVEN DEMOTION GUARDS (No Name Cheats!) ---
    # If the file is labelled Ransomware, we run it through behavioral safety filters:
    if label == "RANSOMWARE":
        # Guard 1: Valid Digital Signatures (Protects signed admin tools)
        if raw_signed == 1 and fusion_prob < 0.98:
            label = "SUSPICIOUS" 
            
        # Guard 2: The Installer Profile (Extreme packing, no malicious shadow deletion)
        # Safely demotes installers that the ML model incorrectly panicked about
        elif raw_entropy > 7.65 and raw_shadow == 0 and fusion_prob < 0.95:
            label = "SUSPICIOUS"
            
    # --- OPTIMIZATION: BUNDLE AUDIT METRICS ---
    disagreement = abs(((p_rf_b + p_xgb_b) / 2) - ((p_rf_a + p_xgb_a) / 2))
    audit_info = {
        "pb_rf": round(p_rf_b, 4),
        "pa_rf": round(p_rf_a, 4),
        "pb_xgb": round(p_xgb_b, 4),
        "pa_xgb": round(p_xgb_a, 4),
        "entropy": round(raw_entropy, 2),
        "size_anomaly": raw_anomaly,
        "shadow_del": raw_shadow,
        "signed": raw_signed,          
        "disagreement": round(disagreement, 4)
    }
            
    return label, fusion_prob, audit_info

# =============================
# MULTICORE WORKERS
# =============================
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

# =============================
# MAIN EVALUATION
# =============================
if __name__ == "__main__":
    print(f"\n🚀 Initializing Multicore Engine ({cpu_count()} cores detected)...")
    
    ransomware_files = collect_files("samples/test/ransomware")
    benign_files = collect_files("samples/test/benign")

    # 1. Process Ransomware
    print(f"\n🦠 Analyzing {len(ransomware_files)} Ransomware samples...")
    with Pool(processes=cpu_count(), initializer=init_worker) as pool:
        results_mal = list(tqdm(pool.imap(process_file_task, ransomware_files), 
                                total=len(ransomware_files), desc="Malware", colour="red"))

    # 2. Process Benign
    print(f"\n🛡️  Analyzing {len(benign_files)} Benign samples...")
    with Pool(processes=cpu_count(), initializer=init_worker) as pool:
        results_ben = list(tqdm(pool.imap(process_file_task, benign_files), 
                                total=len(benign_files), desc="Benign", colour="green"))

    # 3. Aggregate Results & Harvest Audit Logs
    TP = FN = FP = TN = 0
    suspicious_count = 0
    fn_audit_log = []
    fp_audit_log = [] # NEW: Tracks False Positives

    for path, label, prob, audit_info, error in results_mal:
        if error: continue
        if label == "RANSOMWARE": 
            TP += 1
        elif label == "BENIGN": 
            FN += 1
            audit_entry = {"file": os.path.basename(path), "fusion_prob": round(prob, 4), "actual": "MALWARE"}
            audit_entry.update(audit_info)
            fn_audit_log.append(audit_entry)
        else: 
            suspicious_count += 1

    for path, label, prob, audit_info, error in results_ben:
        if error: continue
        if label == "BENIGN": 
            TN += 1
        elif label == "RANSOMWARE": 
            FP += 1
            # INSTANT AUDIT: Capture the False Positives!
            audit_entry = {"file": os.path.basename(path), "fusion_prob": round(prob, 4), "actual": "BENIGN"}
            audit_entry.update(audit_info)
            fp_audit_log.append(audit_entry)
        else: 
            suspicious_count += 1
    
    # 4. Metrics
    total = TP + TN + FP + FN
    if total > 0:
        accuracy = (TP + TN) / total
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        recall = TP / (TP + FN) if (TP + FN) > 0 else 0
        fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        print("\n" + "="*20 + " MULTICORE EVALUATION COMPLETE " + "="*20)
        print(f"Accuracy      : {accuracy:.3f}")
        print(f"Recall        : {recall:.3f}")
        print(f"Precision     : {precision:.3f}")
        print(f"F1 Score      : {f1:.3f}")
        print(f"False PosRate : {fpr:.3f}")
        print(f"Suspicious    : {suspicious_count}")
        print("\nConfusion Matrix:")
        print(f"TP: {TP:4}  FN: {FN:4}")
        print(f"FP: {FP:4}  TN: {TN:4}")
        print("="*70)

    # 5. Save the Instant Audits
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    print("\n🛠️  Generating Forensic Audits...")
    
    # Save False Negatives
    if fn_audit_log:
        fn_path = f"fn_audit_{timestamp}.csv"
        keys = fn_audit_log[0].keys()
        with open(fn_path, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(fn_audit_log)
        print(f"❌ Missed Ransomware : {len(fn_audit_log)} saved to {fn_path}")
    else:
        print("✅ No False Negatives found!")

    # Save False Positives
    if fp_audit_log:
        fp_path = f"fp_audit_{timestamp}.csv"
        keys = fp_audit_log[0].keys()
        with open(fp_path, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(fp_audit_log)
        print(f"⚠️  False Alarms      : {len(fp_audit_log)} saved to {fp_path}\n")
    else:
        print("✅ No False Positives found!\n")
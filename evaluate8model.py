import os
import warnings
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import joblib
import numpy as np

warnings.simplefilter(action='ignore', category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

MALWARE_THRESHOLD = 0.65 
SUSPICIOUS_THRESHOLD = 0.45

SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

def load_models():
    return {
        "rf_behav": joblib.load("rf_behavior_model.joblib"),
        "rf_art": joblib.load("rf_artifact_model.joblib"),
        "xgb_behav": joblib.load("xgb_behavior_model.joblib"),
        "xgb_art": joblib.load("xgb_artifact_model.joblib"),
        "lgbm_behav": joblib.load("lgbm_behavior_model.joblib"),
        "lgbm_art": joblib.load("lgbm_artifact_model.joblib"),
        "cat_behav": joblib.load("catboost_behavior_model.joblib"),
        "cat_art": joblib.load("catboost_artifact_model.joblib"),
        "fusion": joblib.load("fusion_8model.joblib"),
    }

def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files

def build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a, raw_vec):
    probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a])

    avg_behavior = (p_rf_b + p_xgb_b + p_lgbm_b + p_cat_b) / 4
    avg_artifact = (p_rf_a + p_xgb_a + p_lgbm_a + p_cat_a) / 4
    disagreement = abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

    high_artifact_stealth = 1.0 if (avg_artifact > 0.7 and avg_behavior < 0.2) else 0.0
    high_behavior_stealth = 1.0 if (avg_behavior > 0.7 and avg_artifact < 0.2) else 0.0
    joint_conf = avg_artifact * avg_behavior
    max_sig = np.max(probs)
    min_sig = np.min(probs)
    
    raw_silver = np.array(raw_vec)[SILVER_INDICES]

    return np.array([[
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a,
        avg_behavior, avg_artifact,                  
        disagreement, prob_entropy,                  
        high_artifact_stealth,                       
        high_behavior_stealth,                       
        joint_conf,                                  
        max_sig, min_sig,                            
        raw_silver[0], raw_silver[1], raw_silver[2], raw_silver[3]
    ]])

def predict_file(models, filepath):
    feats = extract_features_from_binary(filepath)
    
    raw_shadow = feats.get("SHADOW_COPY_DELETION_STRINGS", 0)
    raw_entropy = feats.get("FILE_ENTROPY", 0.0)
    raw_anomaly = feats.get("VIRTUAL_RAW_SIZE_ANOMALY", 0)
    raw_signed = feats.get("IS_SIGNATURE_VALID", 0) 
    
    raw_vec = vectorize_features(feats)
    vec_np = np.array(raw_vec)

    vec1 = vec_np[MODEL1_INDICES].reshape(1, -1)
    vec2 = vec_np[MODEL2_INDICES].reshape(1, -1)

    p_rf_b = models["rf_behav"].predict_proba(vec1)[0][1]
    p_rf_a = models["rf_art"].predict_proba(vec2)[0][1]
    p_xgb_b = models["xgb_behav"].predict_proba(vec1)[0][1]
    p_xgb_a = models["xgb_art"].predict_proba(vec2)[0][1]
    p_lgbm_b = models["lgbm_behav"].predict_proba(vec1)[0][1]
    p_lgbm_a = models["lgbm_art"].predict_proba(vec2)[0][1]
    p_cat_b = models["cat_behav"].predict_proba(vec1)[0][1]
    p_cat_a = models["cat_art"].predict_proba(vec2)[0][1]

    fusion_input = build_fusion_features(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, p_lgbm_b, p_lgbm_a, p_cat_b, p_cat_a, raw_vec)
    fusion_prob = models["fusion"].predict_proba(fusion_input)[0][1]

    label = "BENIGN"
    if fusion_prob >= MALWARE_THRESHOLD: 
        label = "RANSOMWARE"
    else:
        avg_b = (p_rf_b + p_xgb_b + p_lgbm_b + p_cat_b) / 4
        avg_a = (p_rf_a + p_xgb_a + p_lgbm_a + p_cat_a) / 4
        
        extreme_artifact = (avg_a > 0.85) and (avg_b < 0.20) and raw_signed == 0
        consensus_suspicion = (avg_b > 0.40 and avg_a > 0.40)
        
        if raw_shadow == 1 or extreme_artifact or consensus_suspicion:
            label = "RANSOMWARE"
            fusion_prob = max(fusion_prob, 0.70) 
        elif fusion_prob >= SUSPICIOUS_THRESHOLD: 
            label = "SUSPICIOUS"

    if label == "RANSOMWARE":
        if raw_signed == 1 and fusion_prob < 0.98:
            label = "SUSPICIOUS" 
        elif raw_entropy > 6.8 and raw_shadow == 0 and fusion_prob < 0.95:
            label = "SUSPICIOUS"

    return label, fusion_prob

_worker_models = None

def init_worker():
    global _worker_models
    _worker_models = load_models()

def process_file_task(filepath):
    try:
        label, prob = predict_file(_worker_models, filepath)
        return (filepath, label, prob, None)
    except Exception as e:
        return (filepath, None, None, str(e))

if __name__ == "__main__":
    total_cores = cpu_count()
    half_cores = max(1, total_cores // 2)
    
    print(f"\n🚀 Initializing Multicore Engine (Using {half_cores} of {total_cores} detected cores)...")
    
    ransomware_files = collect_files("samples/test/ransomware")
    benign_files = collect_files("samples/test/benign")

    print(f"\n🦠 Analyzing {len(ransomware_files)} Ransomware samples...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_mal = list(tqdm(pool.imap(process_file_task, ransomware_files), 
                                total=len(ransomware_files), desc="Malware", colour="red"))

    print(f"\n🛡️  Analyzing {len(benign_files)} Benign samples...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_ben = list(tqdm(pool.imap(process_file_task, benign_files), 
                                total=len(benign_files), desc="Benign", colour="green"))

    TP = FN = FP = TN = 0
    suspicious_count = 0

    for path, label, prob, error in results_mal:
        if error: continue
        if label == "RANSOMWARE": TP += 1
        elif label == "BENIGN": FN += 1
        else: suspicious_count += 1

    for path, label, prob, error in results_ben:
        if error: continue
        if label == "BENIGN": TN += 1
        elif label == "RANSOMWARE": FP += 1
        else: suspicious_count += 1
    
    total = TP + TN + FP + FN
    if total > 0:
        accuracy = (TP + TN) / total
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        recall = TP / (TP + FN) if (TP + FN) > 0 else 0
        fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        print("\n" + "="*20 + " 8-MODEL MULTICORE EVALUATION COMPLETE " + "="*20)
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
import os
import warnings
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import joblib
import numpy as np

warnings.simplefilter(action='ignore', category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"
os.environ["OMP_NUM_THREADS"] = "1"

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from feature_schema import FEATURE_SCHEMA

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")
EVAL_THRESHOLD = 0.50  # Hard 0.5 threshold to judge raw ML performance fairly

SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

def load_all_models():
    return {
        "rf": joblib.load("base_rf.joblib"),
        "xgb": joblib.load("base_xgb.joblib"),
        "lgbm": joblib.load("base_lgbm.joblib"),
        "cat": joblib.load("base_cat.joblib"),
        "rf_xgb": joblib.load("fusion_rf_xgb.joblib"),
        "rf_lgbm": joblib.load("fusion_rf_lgbm.joblib"),
        "rf_cat": joblib.load("fusion_rf_cat.joblib"),
        "xgb_lgbm": joblib.load("fusion_xgb_lgbm.joblib"),
        "xgb_cat": joblib.load("fusion_xgb_cat.joblib"),
        "lgbm_cat": joblib.load("fusion_lgbm_cat.joblib"),
        "quad": joblib.load("fusion_quad.joblib")
    }

def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files

def build_pair_meta(p_a, p_b, silver):
    avg_p = (p_a + p_b) / 2
    diff_p = np.abs(p_a - p_b)
    max_p = np.maximum(p_a, p_b)
    min_p = np.minimum(p_a, p_b)
    return np.column_stack([p_a, p_b, avg_p, diff_p, max_p, min_p, silver])

def build_quad_meta(p1, p2, p3, p4, silver):
    probs = np.column_stack([p1, p2, p3, p4])
    avg_p = probs.mean(axis=1)
    std_p = probs.std(axis=1)
    max_p = probs.max(axis=1)
    min_p = probs.min(axis=1)
    entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean(axis=1)
    return np.column_stack([probs, avg_p, std_p, max_p, min_p, entropy, silver])

_worker_models = None

def init_worker():
    global _worker_models
    _worker_models = load_all_models()

def process_file_task(filepath):
    try:
        feats = extract_features_from_binary(filepath)
        vec = np.array(vectorize_features(feats)).reshape(1, -1)
        silver = vec[:, SILVER_INDICES]
        
        p_rf = _worker_models["rf"].predict_proba(vec)[0][1]
        p_xgb = _worker_models["xgb"].predict_proba(vec)[0][1]
        p_lgbm = _worker_models["lgbm"].predict_proba(vec)[0][1]
        p_cat = _worker_models["cat"].predict_proba(vec)[0][1]

        # Evaluate pairs
        p_rf_xgb = _worker_models["rf_xgb"].predict_proba(build_pair_meta(np.array([p_rf]), np.array([p_xgb]), silver))[0][1]
        p_rf_lgbm = _worker_models["rf_lgbm"].predict_proba(build_pair_meta(np.array([p_rf]), np.array([p_lgbm]), silver))[0][1]
        p_rf_cat = _worker_models["rf_cat"].predict_proba(build_pair_meta(np.array([p_rf]), np.array([p_cat]), silver))[0][1]
        p_xgb_lgbm = _worker_models["xgb_lgbm"].predict_proba(build_pair_meta(np.array([p_xgb]), np.array([p_lgbm]), silver))[0][1]
        p_xgb_cat = _worker_models["xgb_cat"].predict_proba(build_pair_meta(np.array([p_xgb]), np.array([p_cat]), silver))[0][1]
        p_lgbm_cat = _worker_models["lgbm_cat"].predict_proba(build_pair_meta(np.array([p_lgbm]), np.array([p_cat]), silver))[0][1]

        # Evaluate Quad
        p_quad = _worker_models["quad"].predict_proba(build_quad_meta(
            np.array([p_rf]), np.array([p_xgb]), np.array([p_lgbm]), np.array([p_cat]), silver
        ))[0][1]

        return {
            "filepath": filepath,
            "RF": p_rf, "XGB": p_xgb, "LGBM": p_lgbm, "CAT": p_cat,
            "RF+XGB": p_rf_xgb, "RF+LGBM": p_rf_lgbm, "RF+CAT": p_rf_cat,
            "XGB+LGBM": p_xgb_lgbm, "XGB+CAT": p_xgb_cat, "LGBM+CAT": p_lgbm_cat,
            "QUAD (All 4)": p_quad,
            "error": None
        }
    except Exception as e:
        return {"filepath": filepath, "error": str(e)}

if __name__ == "__main__":
    total_cores = cpu_count()
    half_cores = max(1, total_cores // 2)
    
    ransomware_files = collect_files("samples/test/ransomware")
    benign_files = collect_files("samples/test/benign")

    print(f"\n🚀 Initializing Multicore Engine (Using {half_cores} of {total_cores} detected cores)...")
    
    print(f"\n🦠 Analyzing {len(ransomware_files)} Ransomware samples...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_mal = list(tqdm(pool.imap(process_file_task, ransomware_files), total=len(ransomware_files), colour="red"))

    print(f"\n🛡️  Analyzing {len(benign_files)} Benign samples...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_ben = list(tqdm(pool.imap(process_file_task, benign_files), total=len(benign_files), colour="green"))

    configurations = [
        "RF", "XGB", "LGBM", "CAT",
        "RF+XGB", "RF+LGBM", "RF+CAT", "XGB+LGBM", "XGB+CAT", "LGBM+CAT",
        "QUAD (All 4)"
    ]

    metrics = {cfg: {"TP": 0, "FN": 0, "FP": 0, "TN": 0} for cfg in configurations}

    for res in results_mal:
        if res["error"]: continue
        for cfg in configurations:
            if res[cfg] >= EVAL_THRESHOLD: metrics[cfg]["TP"] += 1
            else: metrics[cfg]["FN"] += 1

    for res in results_ben:
        if res["error"]: continue
        for cfg in configurations:
            if res[cfg] >= EVAL_THRESHOLD: metrics[cfg]["FP"] += 1
            else: metrics[cfg]["TN"] += 1

    print("\n\n" + "="*85)
    print(" 🏆 FULL MODEL COMBINATION COMPARISON MATRIX")
    print("="*85)
    print(f"| {'Model Configuration':<15} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1 Score':<8} | {'FPR':<8} |")
    print("-" * 85)

    # Sort them into Singles, Pairs, and Quad purely for visual aesthetics
    display_order = configurations

    for i, cfg in enumerate(display_order):
        if i == 4 or i == 10:  # Add separators between sections
            print("-" * 85)
            
        m = metrics[cfg]
        tp, fn, fp, tn = m["TP"], m["FN"], m["FP"], m["TN"]
        total = tp + fn + fp + tn
        
        if total == 0: continue
        
        acc = (tp + tn) / total
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print(f"| {cfg:<15} | {acc:.4f}   | {prec:.4f}    | {rec:.4f}   | {f1:.4f}   | {fpr:.4f}   |")

    print("="*85)
    print("Note: Evaluated at a strict 0.5 Threshold without heuristic guardrails.")
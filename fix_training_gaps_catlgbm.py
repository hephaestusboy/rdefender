"""
=============================================================
 FIX TRAINING DATA GAPS FOR CATBOOST/LGBM ENSEMBLE
=============================================================
"""

import os
import shutil
import json

import numpy as np
import joblib

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from dataset_cache import load_cache, save_cache, file_hash
from feature_schema import FEATURE_SCHEMA


SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")
THRESHOLDS_PATH      = "optimal_thresholds_v2.json"
DATASET_PATH         = "cached_dataset_catlgbm.npz" # Ensure this matches your CatLGBM dataset name

RANSOMWARE_TRAIN_DIR = "samples/ransomware"
BENIGN_TRAIN_DIR     = "samples/benign1"
TEST_RANSOMWARE_DIR  = "samples/test/ransomware"
TEST_BENIGN_DIR      = "samples/test/benign"

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
            return t["malware_threshold"], t["suspicious_threshold"]
    return 0.725, 0.665

def load_models():
    return {
        "lgbm_behav":  joblib.load("lgbm_behavior_model.joblib"),
        "lgbm_art":    joblib.load("lgbm_artifact_model.joblib"),
        "cat_behav":   joblib.load("catboost_behavior_model.joblib"),
        "cat_art":     joblib.load("catboost_artifact_model.joblib"),
        "fusion":      joblib.load("catlgbm_fusion_model.joblib"),
    }

def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files

# =========================================================
# META FEATURES 
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
# PREDICT RAW
# =========================================================

def predict_file_raw(models, filepath, malware_thresh, suspicious_thresh):
    try:
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

        if fusion_prob >= malware_thresh:
            label = "RANSOMWARE"
        elif fusion_prob >= suspicious_thresh:
            label = "SUSPICIOUS"
        else:
            label = "BENIGN"

        return label, fusion_prob, None
    except Exception as e:
        return None, None, str(e)

# =========================================================
# CACHE MANAGEMENT & COPYING
# =========================================================

def remove_from_cache(filepaths: list):
    cache = load_cache()
    removed = 0
    for path in filepaths:
        try:
            h = file_hash(path)
            if h in cache:
                del cache[h]
                removed += 1
        except Exception:
            pass
    save_cache(cache)
    print(f"  Removed {removed} entries from feature cache.")

def safe_copy(src: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    basename = os.path.basename(src)
    dest = os.path.join(dest_dir, basename)

    if os.path.exists(dest):
        if file_hash(src) == file_hash(dest):
            return dest
        stem, ext = os.path.splitext(basename)
        counter = 1
        while os.path.exists(dest):
            dest = os.path.join(dest_dir, f"{stem}_dup{counter}{ext}")
            counter += 1
    shutil.copy2(src, dest)
    return dest

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    print("\n🔍 Loading CatLGBM models for misclassification scan ...")
    models = load_models()
    malware_thresh, suspicious_thresh = load_thresholds()

    fn_files = []
    fp_files = []

    print("\n  Scanning ransomware test files ...")
    for f in collect_files(TEST_RANSOMWARE_DIR):
        label, prob, err = predict_file_raw(models, f, malware_thresh, suspicious_thresh)
        if not err and label == "BENIGN":
            fn_files.append((f, prob))
            print(f"    FN: {os.path.basename(f):50s} prob={prob*100:.1f}%")

    print("\n  Scanning benign test files ...")
    for f in collect_files(TEST_BENIGN_DIR):
        label, prob, err = predict_file_raw(models, f, malware_thresh, suspicious_thresh)
        if not err and label == "RANSOMWARE":
            fp_files.append((f, prob))
            print(f"    FP: {os.path.basename(f):50s} prob={prob*100:.1f}%")

    if not fn_files and not fp_files:
        print("\n  ✅ No misclassified files found — nothing to fix!")
        exit(0)

    print(f"\n📁 Copying misclassified files to training directories ...")
    copied_fn = [safe_copy(src, RANSOMWARE_TRAIN_DIR) for src, _ in fn_files]
    copied_fp = [safe_copy(src, BENIGN_TRAIN_DIR) for src, _ in fp_files]

    print(f"\n🗑️  Clearing feature cache entries for moved files ...")
    remove_from_cache([f for f, _ in fn_files] + [f for f, _ in fp_files])

    if os.path.exists(DATASET_PATH):
        os.remove(DATASET_PATH)
        print(f"  Deleted {DATASET_PATH} — will be rebuilt on next training run.")

    print(f"\n{'='*58}")
    print(f"  DATA GAP FIX COMPLETE (CatLGBM)")
    print(f"{'='*58}")
    print(f"  Added to ransomware training : {len(copied_fn)} files")
    print(f"  Added to benign training     : {len(copied_fp)} files")
    
    print("\n  Next steps:")
    print("    1. Re-run your CatLGBM training script to rebuild dataset + retrain")
    print("    2. Re-run evaluate_catlgbm_ensemble.py")

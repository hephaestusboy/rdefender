import os
import numpy as np
import joblib
from tqdm import tqdm
from multiprocessing import cpu_count
from concurrent.futures import ProcessPoolExecutor, as_completed
from joblib import Parallel, delayed

from sklearn import set_config
set_config(enable_metadata_routing=False)
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning:sklearn.utils.parallel"
os.environ["OMP_NUM_THREADS"] = "1"

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.utils.class_weight import compute_class_weight
from sklearn.calibration import CalibratedClassifierCV
import lightgbm as lgb
from xgboost import XGBClassifier

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from dataset_cache import load_cache, save_cache, file_hash
from feature_schema import FEATURE_SCHEMA

total_cores = cpu_count()
half_cores = max(1, total_cores // 2)

# =========================================================
# HYBRID STACKING: THE "SILVER BULLETS"
# =========================================================
SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

# =========================================================
# MULTICORE DATASET BUILDER
# =========================================================

def extract_single_file(file_info):
    path, label = file_info
    try:
        feats = extract_features_from_binary(path)
        vec = vectorize_features(feats)
        return path, vec, label, None
    except Exception as e:
        return path, None, label, str(e)

def build_dataset_incremental(malware_files, benign_files):
    cache = load_cache()
    X, y = [], []
    todo = []
    all_files = [(p, 1) for p in malware_files] + [(p, 0) for p in benign_files]
    
    print(f"📦 Checking cache for {len(all_files)} files...")
    for path, label in all_files:
        h = file_hash(path)
        if h in cache:
            X.append(cache[h])
            y.append(label)
        else:
            todo.append((path, label))

    if todo:
        print(f"⚡ Parallel Extraction: {len(todo)} files using {half_cores} cores...")
        new_vectors = {}
        with ProcessPoolExecutor(max_workers=half_cores) as executor:
            futures = {executor.submit(extract_single_file, item): item for item in todo}
            for future in tqdm(as_completed(futures), total=len(todo), desc="Extracting", unit="file"):
                path, vec, label, error = future.result()
                if vec is not None:
                    X.append(vec)
                    y.append(label)
                    new_vectors[file_hash(path)] = vec
        
        if new_vectors:
            cache.update(new_vectors)
            save_cache(cache)

    return np.array(X), np.array(y)

# =========================================================
# BASE MODEL FACTORIES
# =========================================================

def build_xgb(y):
    pos, neg = (y == 1).sum(), (y == 0).sum()
    return XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, scale_pos_weight=neg / pos,
        tree_method="hist", eval_metric="logloss", n_jobs=half_cores, random_state=42
    )

def build_lgbm(y):
    classes = np.unique(y)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y)
    return lgb.LGBMClassifier(
        n_estimators=300, max_depth=-1, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, class_weight=dict(zip(classes, weights)),
        n_jobs=half_cores, random_state=42
    )

# =========================================================
# MULTICORE FUSION TASK
# =========================================================

def train_fold(fold_info, X, X1, X2, y):
    fold_idx, (train_idx, val_idx) = fold_info
    
    xgb_b = CalibratedClassifierCV(build_xgb(y[train_idx]), method="isotonic", cv=3).fit(X1[train_idx], y[train_idx])
    xgb_a = CalibratedClassifierCV(build_xgb(y[train_idx]), method="isotonic", cv=3).fit(X2[train_idx], y[train_idx])
    lgbm_b = CalibratedClassifierCV(build_lgbm(y[train_idx]), method="isotonic", cv=3).fit(X1[train_idx], y[train_idx])
    lgbm_a = CalibratedClassifierCV(build_lgbm(y[train_idx]), method="isotonic", cv=3).fit(X2[train_idx], y[train_idx])

    p_xgb_b = xgb_b.predict_proba(X1[val_idx])[:, 1]
    p_xgb_a = xgb_a.predict_proba(X2[val_idx])[:, 1]
    p_lgbm_b = lgbm_b.predict_proba(X1[val_idx])[:, 1]
    p_lgbm_a = lgbm_a.predict_proba(X2[val_idx])[:, 1]

    probs = np.vstack([p_xgb_b, p_xgb_a, p_lgbm_b, p_lgbm_a]).T
    
    avg_behavior = (p_xgb_b + p_lgbm_b) / 2
    avg_artifact = (p_xgb_a + p_lgbm_a) / 2
    disagreement = np.abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean(axis=1)

    high_artifact_stealth = (avg_artifact > 0.7) & (avg_behavior < 0.2)
    high_behavior_stealth = (avg_behavior > 0.7) & (avg_artifact < 0.2)

    meta = np.column_stack([
        p_xgb_b, p_xgb_a, p_lgbm_b, p_lgbm_a, 
        avg_behavior, avg_artifact, disagreement, prob_entropy,
        high_artifact_stealth.astype(float),
        high_behavior_stealth.astype(float),
        (avg_artifact * avg_behavior), 
        (p_lgbm_a - p_xgb_a), (p_lgbm_b - p_xgb_b),
        np.max(probs, axis=1), np.min(probs, axis=1),
        X[val_idx][:, SILVER_INDICES] 
    ])
    
    return meta, y[val_idx]

def build_fusion_dataset_multicore(X, X1, X2, y):
    cv = StratifiedKFold(5, shuffle=True, random_state=42)
    folds = list(enumerate(cv.split(X1, y)))
    print(f"🧠 Building Hybrid Fusion Dataset Parallelly ({len(folds)} Folds)...")
    results = Parallel(n_jobs=half_cores)(delayed(train_fold)(f, X, X1, X2, y) for f in tqdm(folds, desc="Folds"))
    return np.vstack([r[0] for r in results]), np.hstack([r[1] for r in results])

if __name__ == "__main__":
    mal_dir, ben_dir = "samples/ransomware", "samples/benign1"
    mal_files = [os.path.join(mal_dir, f) for f in os.listdir(mal_dir)]
    ben_files = [os.path.join(ben_dir, f) for f in os.listdir(ben_dir)]

    print("=========================================================")
    print(" 🛠️ R-DEFENDER MULTICORE PIPELINE - XGBOOST + LIGHTGBM")
    print("=========================================================")

    if os.path.exists("cached_dataset.npz"):
        data = np.load("cached_dataset.npz")
        X, y = data["X"], data["y"]
    else:
        X, y = build_dataset_incremental(mal_files, ben_files)
        np.savez_compressed("cached_dataset.npz", X=X, y=y)

    X1, X2 = X[:, MODEL1_INDICES], X[:, MODEL2_INDICES]

    print("🚀 Training final calibrated base models...")
    xgb_b = CalibratedClassifierCV(build_xgb(y), method="isotonic", cv=3).fit(X1, y)
    xgb_a = CalibratedClassifierCV(build_xgb(y), method="isotonic", cv=3).fit(X2, y)
    lgbm_b = CalibratedClassifierCV(build_lgbm(y), method="isotonic", cv=3).fit(X1, y)
    lgbm_a = CalibratedClassifierCV(build_lgbm(y), method="isotonic", cv=3).fit(X2, y)

    fusion_X, fusion_y = build_fusion_dataset_multicore(X, X1, X2, y)

    print("🔗 Training Hybrid Meta-Learner...")
    xgb_meta = build_xgb(fusion_y)
    fusion_model = Pipeline([('scaler', StandardScaler()), ('meta_learner', xgb_meta)]).fit(fusion_X, fusion_y)

    joblib.dump(xgb_b, "xgb_behavior_model.joblib")
    joblib.dump(xgb_a, "xgb_artifact_model.joblib")
    joblib.dump(lgbm_b, "lgbm_behavior_model.joblib")
    joblib.dump(lgbm_a, "lgbm_artifact_model.joblib")
    joblib.dump(fusion_model, "xgblgbm_fusion_model.joblib")

    print("✅ Training Complete! Models saved.")
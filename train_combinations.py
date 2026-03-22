import os
import warnings
import numpy as np
import joblib
from tqdm import tqdm
from multiprocessing import cpu_count
from concurrent.futures import ProcessPoolExecutor, as_completed

warnings.filterwarnings("ignore", category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning"
os.environ["OMP_NUM_THREADS"] = "1"

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.utils.class_weight import compute_class_weight
from xgboost import XGBClassifier
import lightgbm as lgb
import catboost as cbt

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from dataset_cache import load_cache, save_cache, file_hash
from feature_schema import FEATURE_SCHEMA

total_cores = cpu_count()
half_cores = max(1, total_cores // 2)

SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

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
            for future in tqdm(as_completed(futures), total=len(todo), desc="Extracting"):
                path, vec, label, error = future.result()
                if vec is not None:
                    X.append(vec)
                    y.append(label)
                    new_vectors[file_hash(path)] = vec
        
        if new_vectors:
            cache.update(new_vectors)
            save_cache(cache)

    return np.array(X), np.array(y)

# ==========================================
# BASE MODEL FACTORIES
# ==========================================
def build_rf(y):
    classes = np.unique(y)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y)
    return RandomForestClassifier(
        n_estimators=400, max_depth=20, min_samples_leaf=2,
        class_weight=dict(zip(classes, weights)), n_jobs=half_cores, random_state=42
    )

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

def build_catboost(y):
    pos = (y == 1).sum()
    neg = (y == 0).sum()
    return cbt.CatBoostClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bylevel=0.8, scale_pos_weight=float(neg / pos),
        thread_count=half_cores, random_state=42, verbose=0
    )

# ==========================================
# META FEATURE BUILDERS
# ==========================================
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

def build_meta_learner():
    xgb_meta = XGBClassifier(
        n_estimators=300, max_depth=4, learning_rate=0.02,
        subsample=0.8, colsample_bytree=0.8, tree_method="hist",
        eval_metric="logloss", n_jobs=half_cores, random_state=42
    )
    return Pipeline([('scaler', StandardScaler()), ('meta', xgb_meta)])

if __name__ == "__main__":
    mal_dir, ben_dir = "samples/ransomware", "samples/benign1"
    mal_files = [os.path.join(mal_dir, f) for f in os.listdir(mal_dir) if os.path.isfile(os.path.join(mal_dir, f))]
    ben_files = [os.path.join(ben_dir, f) for f in os.listdir(ben_dir) if os.path.isfile(os.path.join(ben_dir, f))]

    print("=========================================================")
    print(" 🛠️ TRAINING: RAW BASE MODELS & ALL COMBINATION FUSIONS")
    print("=========================================================")

    if os.path.exists("cached_raw_dataset.npz"):
        data = np.load("cached_raw_dataset.npz")
        X, y = data["X"], data["y"]
        print("Dataset loaded from cache.")
    else:
        X, y = build_dataset_incremental(mal_files, ben_files)
        np.savez_compressed("cached_raw_dataset.npz", X=X, y=y)

    raw_silver = X[:, SILVER_INDICES]

    # Arrays for Out-Of-Fold predictions
    oof_rf = np.zeros(len(y))
    oof_xgb = np.zeros(len(y))
    oof_lgbm = np.zeros(len(y))
    oof_cat = np.zeros(len(y))

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    print("\n🔄 Generating Cross-Validated OOF Predictions for Meta-Learners...")
    for fold, (train_idx, val_idx) in enumerate(cv.split(X, y), 1):
        print(f"  --> Fold {fold}/5")
        X_tr, y_tr = X[train_idx], y[train_idx]
        X_va = X[val_idx]

        m_rf = build_rf(y_tr).fit(X_tr, y_tr)
        m_xgb = build_xgb(y_tr).fit(X_tr, y_tr)
        m_lgbm = build_lgbm(y_tr).fit(X_tr, y_tr)
        m_cat = build_catboost(y_tr).fit(X_tr, y_tr)

        oof_rf[val_idx] = m_rf.predict_proba(X_va)[:, 1]
        oof_xgb[val_idx] = m_xgb.predict_proba(X_va)[:, 1]
        oof_lgbm[val_idx] = m_lgbm.predict_proba(X_va)[:, 1]
        oof_cat[val_idx] = m_cat.predict_proba(X_va)[:, 1]

    print("\n🚀 Training Final Base Models on Full Dataset...")
    final_rf = build_rf(y).fit(X, y)
    final_xgb = build_xgb(y).fit(X, y)
    final_lgbm = build_lgbm(y).fit(X, y)
    final_cat = build_catboost(y).fit(X, y)

    joblib.dump(final_rf, "base_rf.joblib")
    joblib.dump(final_xgb, "base_xgb.joblib")
    joblib.dump(final_lgbm, "base_lgbm.joblib")
    joblib.dump(final_cat, "base_cat.joblib")

    print("✅ Base Models Saved.")

    print("\n🔗 Training Combination Fusion Meta-Learners...")

    combinations = [
        ("rf_xgb", oof_rf, oof_xgb),
        ("rf_lgbm", oof_rf, oof_lgbm),
        ("rf_cat", oof_rf, oof_cat),
        ("xgb_lgbm", oof_xgb, oof_lgbm),
        ("xgb_cat", oof_xgb, oof_cat),
        ("lgbm_cat", oof_lgbm, oof_cat)
    ]

    for name, p_a, p_b in combinations:
        print(f"  --> Training Pair: {name.upper()}")
        meta_X = build_pair_meta(p_a, p_b, raw_silver)
        meta_model = build_meta_learner()
        meta_model.fit(meta_X, y)
        joblib.dump(meta_model, f"fusion_{name}.joblib")

    print("  --> Training Quad: RF+XGB+LGBM+CAT")
    quad_X = build_quad_meta(oof_rf, oof_xgb, oof_lgbm, oof_cat, raw_silver)
    quad_model = build_meta_learner()
    quad_model.fit(quad_X, y)
    joblib.dump(quad_model, "fusion_quad.joblib")

    print("\n✅ All Combination Models Trained and Saved!")
    print("""
    Files Generated:
      - base_rf.joblib
      - base_xgb.joblib
      - base_lgbm.joblib
      - base_cat.joblib
      - fusion_rf_xgb.joblib
      - fusion_rf_lgbm.joblib
      - fusion_rf_cat.joblib
      - fusion_xgb_lgbm.joblib
      - fusion_xgb_cat.joblib
      - fusion_lgbm_cat.joblib
      - fusion_quad.joblib
    """)
"""
Unified training script:
  - 8 calibrated base models: RF/XGB/LGBM/CAT × behavior(MODEL1) / artifact(MODEL2)
  - 4 single models on full features: base_rf, base_xgb, base_lgbm, base_cat
  - 6 pair fusions + 1 quad fusion (for evaluate_combinations.py)
  - 1 eight-model meta-learner fusion (for evaluate8model.py)
"""

import os
import warnings
import numpy as np
import joblib
from tqdm import tqdm
from multiprocessing import cpu_count
from concurrent.futures import ProcessPoolExecutor, as_completed
from joblib import Parallel, delayed

warnings.filterwarnings("ignore", category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning"
os.environ["OMP_NUM_THREADS"] = "1"

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.utils.class_weight import compute_class_weight
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
import lightgbm as lgb
import catboost as cbt

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
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

# ─── Dataset ──────────────────────────────────────────────────────────────────

def _extract_single(file_info):
    path, label = file_info
    try:
        vec = vectorize_features(extract_features_from_binary(path))
        return path, vec, label, None
    except Exception as e:
        return path, None, label, str(e)

def build_dataset(malware_files, benign_files, cache_path="cached_unified_dataset.npz"):
    if os.path.exists(cache_path):
        data = np.load(cache_path)
        print("Dataset loaded from cache.")
        return data["X"], data["y"]

    cache = load_cache()
    X, y, todo = [], [], []
    for path, label in [(p, 1) for p in malware_files] + [(p, 0) for p in benign_files]:
        h = file_hash(path)
        if h in cache:
            X.append(cache[h]); y.append(label)
        else:
            todo.append((path, label))

    if todo:
        print(f"⚡ Extracting {len(todo)} files on {half_cores} cores...")
        new_vecs = {}
        with ProcessPoolExecutor(max_workers=half_cores) as ex:
            futures = {ex.submit(_extract_single, item): item for item in todo}
            for fut in tqdm(as_completed(futures), total=len(todo), desc="Extracting"):
                path, vec, label, err = fut.result()
                if vec is not None:
                    X.append(vec); y.append(label)
                    new_vecs[file_hash(path)] = vec
        if new_vecs:
            cache.update(new_vecs); save_cache(cache)

    X, y = np.array(X), np.array(y)
    np.savez_compressed(cache_path, X=X, y=y)
    return X, y

# ─── Model factories ──────────────────────────────────────────────────────────

def build_rf(y):
    classes = np.unique(y)
    w = compute_class_weight("balanced", classes=classes, y=y)
    return RandomForestClassifier(
        n_estimators=400, max_depth=20, min_samples_leaf=2,
        class_weight=dict(zip(classes, w)), n_jobs=half_cores, random_state=42
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
    w = compute_class_weight("balanced", classes=classes, y=y)
    return lgb.LGBMClassifier(
        n_estimators=300, max_depth=-1, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, class_weight=dict(zip(classes, w)),
        n_jobs=half_cores, random_state=42
    )

def build_cat(y):
    pos, neg = (y == 1).sum(), (y == 0).sum()
    return cbt.CatBoostClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bylevel=0.8, scale_pos_weight=float(neg / pos),
        thread_count=half_cores, random_state=42, verbose=0
    )

def calibrated(model):
    return CalibratedClassifierCV(model, method="isotonic", cv=3)

def meta_learner():
    return Pipeline([
        ("scaler", StandardScaler()),
        ("meta", XGBClassifier(
            n_estimators=300, max_depth=4, learning_rate=0.02,
            subsample=0.8, colsample_bytree=0.8, tree_method="hist",
            eval_metric="logloss", n_jobs=half_cores, random_state=42
        ))
    ])

# ─── Meta feature builders ────────────────────────────────────────────────────

def pair_meta(pa, pb, silver):
    return np.column_stack([pa, pb, (pa+pb)/2, np.abs(pa-pb), np.maximum(pa,pb), np.minimum(pa,pb), silver])

def quad_meta(p1, p2, p3, p4, silver):
    probs = np.column_stack([p1, p2, p3, p4])
    avg = probs.mean(1); std = probs.std(1)
    entropy = -(probs * np.log(probs+1e-9) + (1-probs)*np.log(1-probs+1e-9)).mean(1)
    return np.column_stack([probs, avg, std, probs.max(1), probs.min(1), entropy, silver])

def eight_model_meta(p_rb, p_ra, p_xb, p_xa, p_lb, p_la, p_cb, p_ca, X_full):
    probs = np.column_stack([p_rb, p_ra, p_xb, p_xa, p_lb, p_la, p_cb, p_ca])
    avg_b = (p_rb + p_xb + p_lb + p_cb) / 4
    avg_a = (p_ra + p_xa + p_la + p_ca) / 4
    disagree = np.abs(avg_b - avg_a)
    entropy = -(probs * np.log(probs+1e-9) + (1-probs)*np.log(1-probs+1e-9)).mean(1)
    art_stealth = ((avg_a > 0.7) & (avg_b < 0.2)).astype(float)
    beh_stealth = ((avg_b > 0.7) & (avg_a < 0.2)).astype(float)
    silver = X_full[:, SILVER_INDICES]
    return np.column_stack([
        probs, avg_b, avg_a, disagree, entropy,
        art_stealth, beh_stealth, avg_a * avg_b,
        probs.max(1), probs.min(1), silver
    ])

# ─── OOF fold worker for 8-model meta ─────────────────────────────────────────

def _fold_8model(fold_info, X, X1, X2, y):
    _, (tr, va) = fold_info
    ytr = y[tr]

    rb = calibrated(build_rf(ytr)).fit(X1[tr], ytr)
    ra = calibrated(build_rf(ytr)).fit(X2[tr], ytr)
    xb = calibrated(build_xgb(ytr)).fit(X1[tr], ytr)
    xa = calibrated(build_xgb(ytr)).fit(X2[tr], ytr)
    lb = calibrated(build_lgbm(ytr)).fit(X1[tr], ytr)
    la = calibrated(build_lgbm(ytr)).fit(X2[tr], ytr)
    cb = calibrated(build_cat(ytr)).fit(X1[tr], ytr)
    ca = calibrated(build_cat(ytr)).fit(X2[tr], ytr)

    def p(m, Xv): return m.predict_proba(Xv)[:, 1]

    meta = eight_model_meta(
        p(rb, X1[va]), p(ra, X2[va]),
        p(xb, X1[va]), p(xa, X2[va]),
        p(lb, X1[va]), p(la, X2[va]),
        p(cb, X1[va]), p(ca, X2[va]),
        X[va]
    )
    return meta, y[va]

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mal_dir, ben_dir = "samples/ransomware", "samples/benign1"
    mal_files = [os.path.join(mal_dir, f) for f in os.listdir(mal_dir) if os.path.isfile(os.path.join(mal_dir, f))]
    ben_files = [os.path.join(ben_dir, f) for f in os.listdir(ben_dir) if os.path.isfile(os.path.join(ben_dir, f))]

    print("=" * 60)
    print(" 🛠️  UNIFIED 8-MODEL + COMBINATION FUSION TRAINING PIPELINE")
    print("=" * 60)

    X, y = build_dataset(mal_files, ben_files)
    X1, X2 = X[:, MODEL1_INDICES], X[:, MODEL2_INDICES]
    silver = X[:, SILVER_INDICES]

    # ── Phase 1: OOF predictions for combination fusions ──────────────────────
    print("\n📊 Phase 1: Cross-validated OOF predictions for combination fusions...")
    oof = {k: np.zeros(len(y)) for k in ("rf", "xgb", "lgbm", "cat")}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for fold, (tr, va) in enumerate(cv.split(X, y), 1):
        print(f"  Fold {fold}/5")
        ytr = y[tr]
        oof["rf"][va]   = build_rf(ytr).fit(X[tr], ytr).predict_proba(X[va])[:, 1]
        oof["xgb"][va]  = build_xgb(ytr).fit(X[tr], ytr).predict_proba(X[va])[:, 1]
        oof["lgbm"][va] = build_lgbm(ytr).fit(X[tr], ytr).predict_proba(X[va])[:, 1]
        oof["cat"][va]  = build_cat(ytr).fit(X[tr], ytr).predict_proba(X[va])[:, 1]

    # ── Phase 2: Train & save 4 full-feature base models ──────────────────────
    print("\n🚀 Phase 2: Training 4 full-feature base models...")
    base_rf   = build_rf(y).fit(X, y);   joblib.dump(base_rf,   "base_rf.joblib")
    base_xgb  = build_xgb(y).fit(X, y);  joblib.dump(base_xgb,  "base_xgb.joblib")
    base_lgbm = build_lgbm(y).fit(X, y); joblib.dump(base_lgbm, "base_lgbm.joblib")
    base_cat  = build_cat(y).fit(X, y);  joblib.dump(base_cat,  "base_cat.joblib")
    print("  ✅ base_rf / base_xgb / base_lgbm / base_cat saved.")

    # ── Phase 3: Train pair + quad combination fusions ────────────────────────
    print("\n🔗 Phase 3: Training pair & quad combination fusions...")
    pairs = [
        ("rf_xgb",   oof["rf"],   oof["xgb"]),
        ("rf_lgbm",  oof["rf"],   oof["lgbm"]),
        ("rf_cat",   oof["rf"],   oof["cat"]),
        ("xgb_lgbm", oof["xgb"],  oof["lgbm"]),
        ("xgb_cat",  oof["xgb"],  oof["cat"]),
        ("lgbm_cat", oof["lgbm"], oof["cat"]),
    ]
    for name, pa, pb in pairs:
        m = meta_learner().fit(pair_meta(pa, pb, silver), y)
        joblib.dump(m, f"fusion_{name}.joblib")
        print(f"  ✅ fusion_{name}.joblib saved.")

    quad_m = meta_learner().fit(quad_meta(oof["rf"], oof["xgb"], oof["lgbm"], oof["cat"], silver), y)
    joblib.dump(quad_m, "fusion_quad.joblib")
    print("  ✅ fusion_quad.joblib saved.")

    # ── Phase 4: Train 8 calibrated behavior/artifact models ──────────────────
    print("\n🧠 Phase 4: Training 8 calibrated behavior/artifact models...")
    rf_b  = calibrated(build_rf(y)).fit(X1, y);   joblib.dump(rf_b,  "rf_behavior_model.joblib")
    rf_a  = calibrated(build_rf(y)).fit(X2, y);   joblib.dump(rf_a,  "rf_artifact_model.joblib")
    xgb_b = calibrated(build_xgb(y)).fit(X1, y);  joblib.dump(xgb_b, "xgb_behavior_model.joblib")
    xgb_a = calibrated(build_xgb(y)).fit(X2, y);  joblib.dump(xgb_a, "xgb_artifact_model.joblib")
    lgbm_b = calibrated(build_lgbm(y)).fit(X1, y); joblib.dump(lgbm_b, "lgbm_behavior_model.joblib")
    lgbm_a = calibrated(build_lgbm(y)).fit(X2, y); joblib.dump(lgbm_a, "lgbm_artifact_model.joblib")
    cat_b  = calibrated(build_cat(y)).fit(X1, y);  joblib.dump(cat_b,  "catboost_behavior_model.joblib")
    cat_a  = calibrated(build_cat(y)).fit(X2, y);  joblib.dump(cat_a,  "catboost_artifact_model.joblib")
    print("  ✅ All 8 behavior/artifact models saved.")

    # ── Phase 5: OOF for 8-model meta-learner ─────────────────────────────────
    print("\n🔄 Phase 5: Building OOF meta-features for 8-model fusion...")
    folds = list(enumerate(cv.split(X1, y)))
    results = Parallel(n_jobs=half_cores)(
        delayed(_fold_8model)(f, X, X1, X2, y) for f in tqdm(folds, desc="8-model folds")
    )
    fusion_X = np.vstack([r[0] for r in results])
    fusion_y = np.hstack([r[1] for r in results])

    print("\n🔗 Phase 5b: Training 8-model meta-learner...")
    fusion_8 = Pipeline([
        ("scaler", StandardScaler()),
        ("meta", XGBClassifier(
            n_estimators=600, max_depth=6, learning_rate=0.02,
            scale_pos_weight=3.0, subsample=0.8, colsample_bytree=0.8,
            tree_method="hist", eval_metric="logloss", n_jobs=half_cores, random_state=42
        ))
    ])
    fusion_8.fit(fusion_X, fusion_y)
    joblib.dump(fusion_8, "fusion_8model.joblib")
    print("  ✅ fusion_8model.joblib saved.")

    print("\n" + "=" * 60)
    print(" ✅ ALL MODELS TRAINED AND SAVED")
    print("=" * 60)
    print("""
  Base (full features):
    base_rf.joblib, base_xgb.joblib, base_lgbm.joblib, base_cat.joblib

  Pair fusions:
    fusion_rf_xgb.joblib, fusion_rf_lgbm.joblib, fusion_rf_cat.joblib
    fusion_xgb_lgbm.joblib, fusion_xgb_cat.joblib, fusion_lgbm_cat.joblib

  Quad fusion:
    fusion_quad.joblib

  8-model behavior/artifact:
    rf_behavior_model.joblib, rf_artifact_model.joblib
    xgb_behavior_model.joblib, xgb_artifact_model.joblib
    lgbm_behavior_model.joblib, lgbm_artifact_model.joblib
    catboost_behavior_model.joblib, catboost_artifact_model.joblib

  8-model meta-learner:
    fusion_8model.joblib
    """)

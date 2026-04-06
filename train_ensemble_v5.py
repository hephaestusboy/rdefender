import os
import sys
import glob
import json
import csv as _csv
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
import warnings as _w
_w.filterwarnings("ignore", message="X does not have valid feature names")

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, train_test_split
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
half_cores  = max(1, total_cores // 2)

# =========================================================
# CONFIG
# =========================================================
MAL_DIR         = "samples/ransomware"
BEN_DIR         = "samples/benign1"
TEST_MAL_DIR    = "samples/test/ransomware"
TEST_BEN_DIR    = "samples/test/benign"
CACHE_FILE      = "cached_dataset.npz"
THRESHOLD_FILE  = "thresholds_v5.json"
AUDIT_GLOB_FN   = "fn_audit_v5_*.csv"
AUDIT_GLOB_FP   = "fp_audit_v5_*.csv"
OVERSAMPLE_RATE = 3
VAL_SPLIT       = 0.20
THRESH_MIN      = 0.20
THRESH_MAX      = 0.70
THRESH_STEP     = 0.01
FPR_BUDGET      = 0.01
N_ITERATIONS    = 100

# Hyperparameter search space
SEARCH_SPACE = {
    "rf_n_estimators":   [200, 300, 400, 500],
    "rf_max_depth":      [12, 16, 20, 25, None],
    "rf_recall_boost":   [1.2, 1.5, 1.8],
    "xgb_n_estimators":  [200, 300, 400],
    "xgb_max_depth":     [4, 5, 6, 7],
    "xgb_lr":            [0.03, 0.05, 0.08],
    "xgb_spw_mult":      [1.2, 1.5, 1.8],
    "lgbm_n_estimators": [200, 300, 400],
    "lgbm_lr":           [0.03, 0.05, 0.08],
    "lgbm_recall_boost": [1.2, 1.5, 1.8],
    "cat_n_estimators":  [200, 300, 400],
    "cat_depth":         [4, 5, 6, 7],
    "cat_lr":            [0.03, 0.05, 0.08],
    "cat_spw_mult":      [1.2, 1.5, 1.8],
    "meta_n_estimators": [400, 600, 800],
    "meta_max_depth":    [4, 5, 6],
    "meta_lr":           [0.005, 0.01, 0.02],
    "meta_spw":          [3.0, 4.0, 6.0, 8.0],
    "meta_subsample":    [0.7, 0.8, 0.9],
    "meta_colsample":    [0.7, 0.8, 0.9],
}

DEFAULT_HP = {
    "rf_n_estimators": 400, "rf_max_depth": 20, "rf_recall_boost": 1.5,
    "xgb_n_estimators": 300, "xgb_max_depth": 6, "xgb_lr": 0.05, "xgb_spw_mult": 1.5,
    "lgbm_n_estimators": 300, "lgbm_lr": 0.05, "lgbm_recall_boost": 1.5,
    "cat_n_estimators": 300, "cat_depth": 6, "cat_lr": 0.05, "cat_spw_mult": 1.5,
    "meta_n_estimators": 800, "meta_max_depth": 6, "meta_lr": 0.01,
    "meta_spw": 6.0, "meta_subsample": 0.8, "meta_colsample": 0.8,
}

SILVER_BULLETS = [
    "IS_SIGNATURE_VALID",
    "SHADOW_COPY_DELETION_STRINGS",
    "VIRTUAL_RAW_SIZE_ANOMALY",
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

# =========================================================
# DATASET BUILDER
# =========================================================

def _extract_single(file_info):
    path, label = file_info
    try:
        vec = vectorize_features(extract_features_from_binary(path))
        return path, vec, label, None
    except Exception as e:
        return path, None, label, str(e)

def build_dataset_incremental(malware_files, benign_files):
    cache = load_cache()
    X, y, todo = [], [], []
    all_files = [(p, 1) for p in malware_files] + [(p, 0) for p in benign_files]

    print(f"📦 Checking cache for {len(all_files)} files...")
    for path, label in all_files:
        h = file_hash(path)
        if h in cache:
            X.append(cache[h]); y.append(label)
        else:
            todo.append((path, label))

    if todo:
        print(f"⚡ Parallel Extraction: {len(todo)} files using {half_cores} cores...")
        new_vectors = {}
        with ProcessPoolExecutor(max_workers=half_cores) as executor:
            futures = {executor.submit(_extract_single, item): item for item in todo}
            for future in tqdm(as_completed(futures), total=len(todo), desc="Extracting", unit="file"):
                path, vec, label, error = future.result()
                if vec is not None:
                    X.append(vec); y.append(label)
                    new_vectors[file_hash(path)] = vec
        if new_vectors:
            cache.update(new_vectors); save_cache(cache)

    return np.array(X), np.array(y)

# =========================================================
# MODEL FACTORIES
# =========================================================

def build_rf(y, hp, seed):
    classes = np.unique(y)
    w = compute_class_weight("balanced", classes=classes, y=y)
    w_dict = dict(zip(classes, w))
    w_dict[1] *= hp["rf_recall_boost"]
    return RandomForestClassifier(
        n_estimators=hp["rf_n_estimators"], max_depth=hp["rf_max_depth"],
        min_samples_leaf=2, class_weight=w_dict, n_jobs=half_cores, random_state=seed
    )

def build_xgb(y, hp, seed):
    pos, neg = (y == 1).sum(), (y == 0).sum()
    return XGBClassifier(
        n_estimators=hp["xgb_n_estimators"], max_depth=hp["xgb_max_depth"],
        learning_rate=hp["xgb_lr"], subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=(neg / pos) * hp["xgb_spw_mult"],
        tree_method="hist", eval_metric="logloss", n_jobs=half_cores, random_state=seed
    )

def build_lgbm(y, hp, seed):
    classes = np.unique(y)
    w = compute_class_weight("balanced", classes=classes, y=y)
    w_dict = dict(zip(classes, w))
    w_dict[1] *= hp["lgbm_recall_boost"]
    return lgb.LGBMClassifier(
        n_estimators=hp["lgbm_n_estimators"], max_depth=-1,
        learning_rate=hp["lgbm_lr"], subsample=0.8, colsample_bytree=0.8,
        class_weight=w_dict, n_jobs=half_cores, random_state=seed, verbose=-1
    )

def build_cat(y, hp, seed):
    pos, neg = (y == 1).sum(), (y == 0).sum()
    return cbt.CatBoostClassifier(
        n_estimators=hp["cat_n_estimators"], max_depth=hp["cat_depth"],
        learning_rate=hp["cat_lr"], subsample=0.8, colsample_bylevel=0.8,
        scale_pos_weight=float((neg / pos) * hp["cat_spw_mult"]),
        thread_count=half_cores, random_state=seed, verbose=0
    )

def calibrated(model):
    return CalibratedClassifierCV(model, method="isotonic", cv=3)

# =========================================================
# FOLD WORKER — 8-model meta array
#
#  1-8  : p_rb, p_ra, p_xb, p_xa, p_lb, p_la, p_cb, p_ca
#  9-10 : avg_behavior, avg_artifact
#  11   : disagreement
#  12   : prob_entropy
#  13-14: high_artifact_stealth, high_behavior_stealth
#  15   : joint_conf
#  16-19: per-algo behavior-artifact deltas (rf, xgb, lgbm, cat)
#  20-21: max_sig, min_sig
#  22-25: silver bullets
#  26   : extreme_artifact_loose
#  27   : extreme_behavior_loose
#  28   : consensus_soft
#  29   : behavior_dominance
#  30   : signed x avg_prob       (FP suppression)
#  31   : entropy x avg_prob      (FP suppression)
#  32   : std across all 8 probs  (uncertainty)
# =========================================================

def _build_meta(p_rb, p_ra, p_xb, p_xa, p_lb, p_la, p_cb, p_ca, X_full):
    probs        = np.column_stack([p_rb, p_ra, p_xb, p_xa, p_lb, p_la, p_cb, p_ca])
    avg_behavior = (p_rb + p_xb + p_lb + p_cb) / 4
    avg_artifact = (p_ra + p_xa + p_la + p_ca) / 4
    disagreement = np.abs(avg_behavior - avg_artifact)
    prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean(axis=1)

    high_artifact_stealth  = ((avg_artifact > 0.7)  & (avg_behavior < 0.2)).astype(float)
    high_behavior_stealth  = ((avg_behavior > 0.7)  & (avg_artifact < 0.2)).astype(float)
    extreme_artifact_loose = ((avg_artifact > 0.75) & (avg_behavior < 0.30)).astype(float)
    extreme_behavior_loose = ((avg_behavior > 0.75) & (avg_artifact < 0.30)).astype(float)
    consensus_soft         = ((avg_behavior > 0.30) & (avg_artifact > 0.30)).astype(float)
    behavior_dominance     = np.maximum(0.0, avg_behavior - avg_artifact)

    raw_silver     = X_full[:, SILVER_INDICES]
    avg_prob       = (avg_behavior + avg_artifact) / 2
    signed_x_prob  = raw_silver[:, 0] * avg_prob
    entropy_x_prob = (raw_silver[:, 3] / 8.0) * avg_prob
    prob_std       = probs.std(axis=1)

    return np.column_stack([
        probs,
        avg_behavior, avg_artifact,
        disagreement, prob_entropy,
        high_artifact_stealth, high_behavior_stealth,
        avg_artifact * avg_behavior,
        (p_ra - p_rb), (p_xa - p_xb), (p_la - p_lb), (p_ca - p_cb),
        probs.max(axis=1), probs.min(axis=1),
        raw_silver,
        extreme_artifact_loose, extreme_behavior_loose,
        consensus_soft, behavior_dominance,
        signed_x_prob, entropy_x_prob,
        prob_std,
    ])

def train_fold(fold_info, X, X1, X2, y, hp, seed):
    _, (tr, va) = fold_info
    ytr = y[tr]

    rb = calibrated(build_rf(ytr,   hp, seed)).fit(X1[tr], ytr)
    ra = calibrated(build_rf(ytr,   hp, seed)).fit(X2[tr], ytr)
    xb = calibrated(build_xgb(ytr,  hp, seed)).fit(X1[tr], ytr)
    xa = calibrated(build_xgb(ytr,  hp, seed)).fit(X2[tr], ytr)
    lb = calibrated(build_lgbm(ytr, hp, seed)).fit(X1[tr], ytr)
    la = calibrated(build_lgbm(ytr, hp, seed)).fit(X2[tr], ytr)
    cb = calibrated(build_cat(ytr,  hp, seed)).fit(X1[tr], ytr)
    ca = calibrated(build_cat(ytr,  hp, seed)).fit(X2[tr], ytr)

    def p(m, Xv): return m.predict_proba(Xv)[:, 1]

    meta = _build_meta(
        p(rb, X1[va]), p(ra, X2[va]),
        p(xb, X1[va]), p(xa, X2[va]),
        p(lb, X1[va]), p(la, X2[va]),
        p(cb, X1[va]), p(ca, X2[va]),
        X[va]
    )
    return meta, y[va]

def build_fusion_dataset(X, X1, X2, y, hp, seed):
    cv    = StratifiedKFold(5, shuffle=True, random_state=seed)
    folds = list(enumerate(cv.split(X1, y)))
    print(f"   🧠 Building Fusion Dataset ({len(folds)} folds)...")
    results = [train_fold(f, X, X1, X2, y, hp, seed) for f in tqdm(folds, desc="   Folds")]
    return np.vstack([r[0] for r in results]), np.hstack([r[1] for r in results])

# =========================================================
# ITERATION SCORING
# =========================================================

def _score(recall, fpr):
    if recall >= 0.99 and fpr <= FPR_BUDGET:
        return 1.0 + (FPR_BUDGET - fpr)
    return recall * 0.6 - fpr * 0.4

def _threshold_search(val_probs, fy_val):
    best_thresh, best_recall, best_fpr = 0.50, 0.0, 1.0
    fallback_thresh, fallback_recall   = 0.50, 0.0
    for t in np.arange(THRESH_MIN, THRESH_MAX + THRESH_STEP, THRESH_STEP):
        preds = (val_probs >= t).astype(int)
        tp = int(((preds == 1) & (fy_val == 1)).sum())
        fn = int(((preds == 0) & (fy_val == 1)).sum())
        fp = int(((preds == 1) & (fy_val == 0)).sum())
        tn = int(((preds == 0) & (fy_val == 0)).sum())
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr    = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        if recall > fallback_recall or (recall == fallback_recall and round(float(t), 2) > fallback_thresh):
            fallback_recall = recall; fallback_thresh = round(float(t), 2)
        if fpr <= FPR_BUDGET and recall > best_recall:
            best_recall, best_fpr, best_thresh = recall, fpr, round(float(t), 2)
    if best_recall == 0.0:
        best_thresh, best_recall = fallback_thresh, fallback_recall
    return best_thresh, best_recall, best_fpr

def run_iteration(iteration, seed, hp, X, X1, X2, y, fusion_X, fusion_y):
    print(f"\n{'─'*60}")
    print(f"  Iteration {iteration+1}/{N_ITERATIONS}  seed={seed}")
    print(f"  rf({hp['rf_n_estimators']}est d={hp['rf_max_depth']} boost={hp['rf_recall_boost']})  "
          f"xgb({hp['xgb_n_estimators']}est d={hp['xgb_max_depth']} lr={hp['xgb_lr']})  "
          f"lgbm({hp['lgbm_n_estimators']}est lr={hp['lgbm_lr']})  "
          f"cat({hp['cat_n_estimators']}est d={hp['cat_depth']} lr={hp['cat_lr']})")
    print(f"  meta({hp['meta_n_estimators']}est d={hp['meta_max_depth']} lr={hp['meta_lr']} spw={hp['meta_spw']})")
    print(f"{'─'*60}")

    rb = calibrated(build_rf(y,   hp, seed)).fit(X1, y)
    ra = calibrated(build_rf(y,   hp, seed)).fit(X2, y)
    xb = calibrated(build_xgb(y,  hp, seed)).fit(X1, y)
    xa = calibrated(build_xgb(y,  hp, seed)).fit(X2, y)
    lb = calibrated(build_lgbm(y, hp, seed)).fit(X1, y)
    la = calibrated(build_lgbm(y, hp, seed)).fit(X2, y)
    cb = calibrated(build_cat(y,  hp, seed)).fit(X1, y)
    ca = calibrated(build_cat(y,  hp, seed)).fit(X2, y)

    xgb_meta = XGBClassifier(
        n_estimators=hp["meta_n_estimators"], max_depth=hp["meta_max_depth"],
        learning_rate=hp["meta_lr"], scale_pos_weight=hp["meta_spw"],
        subsample=hp["meta_subsample"], colsample_bytree=hp["meta_colsample"],
        tree_method="hist", eval_metric="logloss", n_jobs=half_cores, random_state=seed
    )
    fusion_model = Pipeline([("scaler", StandardScaler()), ("meta_learner", xgb_meta)])
    fX_tr, fX_val, fy_tr, fy_val = train_test_split(
        fusion_X, fusion_y, test_size=VAL_SPLIT, stratify=fusion_y, random_state=seed
    )
    fusion_model.fit(fX_tr, fy_tr)

    val_probs = fusion_model.predict_proba(fX_val)[:, 1]
    thresh, recall, fpr = _threshold_search(val_probs, fy_val)
    score = _score(recall, fpr)

    tag = "✅" if (recall >= 0.99 and fpr <= FPR_BUDGET) else "  "
    print(f"  {tag} recall={recall:.4f}  FPR={fpr:.4f}  threshold={thresh}  score={score:.5f}")

    return score, thresh, recall, fpr, rb, ra, xb, xa, lb, la, cb, ca, fusion_model

# =========================================================
# RETARGET SUPPORT
# =========================================================

def load_retarget_files():
    def latest(pattern):
        files = sorted(glob.glob(pattern))
        return files[-1] if files else None

    fn_path = latest(AUDIT_GLOB_FN)
    fp_path = latest(AUDIT_GLOB_FP)
    extra_mal, extra_ben = [], []

    if fn_path and os.path.exists(fn_path):
        with open(fn_path) as f:
            for row in _csv.DictReader(f):
                if row.get("verdict", "BENIGN") == "SUSPICIOUS":
                    continue
                candidate = os.path.join(TEST_MAL_DIR, row["file"])
                if os.path.exists(candidate):
                    extra_mal.append(candidate)
        print(f"  Retarget FN: {len(extra_mal)} files from {fn_path}")

    if fp_path and os.path.exists(fp_path):
        with open(fp_path) as f:
            for row in _csv.DictReader(f):
                if row.get("verdict", "RANSOMWARE") == "SUSPICIOUS":
                    continue
                candidate = os.path.join(TEST_BEN_DIR, row["file"])
                if os.path.exists(candidate):
                    extra_ben.append(candidate)
        print(f"  Retarget FP: {len(extra_ben)} files from {fp_path}")

    return extra_mal, extra_ben

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    retarget = "--retarget" in sys.argv

    mal_files = [os.path.join(MAL_DIR, f) for f in os.listdir(MAL_DIR) if os.path.isfile(os.path.join(MAL_DIR, f))]
    ben_files = [os.path.join(BEN_DIR, f) for f in os.listdir(BEN_DIR) if os.path.isfile(os.path.join(BEN_DIR, f))]

    print("=========================================================")
    print(" 🛠️  R-DEFENDER ENSEMBLE v5 — 8-MODEL RECALL-BIASED FUSION")
    if retarget:
        print(" 🎯 RETARGET MODE — FN/FP injection active")
    print("=========================================================")

    if os.path.exists(CACHE_FILE):
        data = np.load(CACHE_FILE)
        X, y = data["X"], data["y"]
        print("Dataset loaded from cache.")
    else:
        X, y = build_dataset_incremental(mal_files, ben_files)
        np.savez_compressed(CACHE_FILE, X=X, y=y)

    if retarget:
        extra_mal, extra_ben = load_retarget_files()
        extra_X_mal, extra_X_ben = [], []
        if extra_mal:
            Xm, _ = build_dataset_incremental(extra_mal, [])
            extra_X_mal = list(Xm)
        if extra_ben:
            Xb, _ = build_dataset_incremental([], extra_ben)
            extra_X_ben = list(Xb)
        blocks_X, blocks_y = [X], [y]
        if extra_X_mal:
            arr = np.array(extra_X_mal)
            for _ in range(OVERSAMPLE_RATE):
                blocks_X.append(arr); blocks_y.append(np.ones(len(arr), dtype=int))
        if extra_X_ben:
            arr = np.array(extra_X_ben)
            for _ in range(OVERSAMPLE_RATE):
                blocks_X.append(arr); blocks_y.append(np.zeros(len(arr), dtype=int))
        X = np.vstack(blocks_X); y = np.hstack(blocks_y)
        print(f"  Dataset after injection+oversample: {(y==1).sum()} malware, {(y==0).sum()} benign")

    X1, X2 = X[:, MODEL1_INDICES], X[:, MODEL2_INDICES]

    rng = np.random.default_rng(42)
    print("\n🧠 Building OOF Fusion Dataset (shared across iterations)...")
    fusion_X, fusion_y = build_fusion_dataset(X, X1, X2, y, DEFAULT_HP, 42)

    print(f"\n🔁 Starting {N_ITERATIONS} training iterations...")
    best_score = -np.inf
    best_state = None
    history    = []

    for i in range(N_ITERATIONS):
        seed = int(rng.integers(0, 10_000))
        hp   = {k: v[int(rng.integers(0, len(v)))] for k, v in SEARCH_SPACE.items()}
        if i == 0:
            seed = 42
            hp   = DEFAULT_HP.copy()

        result = run_iteration(i, seed, hp, X, X1, X2, y, fusion_X, fusion_y)
        score, thresh, recall, fpr = result[:4]
        history.append((i + 1, seed, recall, fpr, thresh, score))

        if score > best_score:
            best_score = score
            best_state = result
            print(f"  🏆 New best (iteration {i+1})  score={score:.5f}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  ITERATION SUMMARY")
    print(f"  {'Iter':>4}  {'Seed':>5}  {'Recall':>7}  {'FPR':>7}  {'Thresh':>6}  {'Score':>8}")
    print(f"  {'─'*4}  {'─'*5}  {'─'*7}  {'─'*7}  {'─'*6}  {'─'*8}")
    for it, sd, rc, fp_, th, sc in history:
        marker = " ◄ best" if sc == best_score else ""
        print(f"  {it:>4}  {sd:>5}  {rc:.4f}  {fp_:.4f}  {th:>6}  {sc:>8.5f}{marker}")
    print(f"{'═'*60}")

    # ── Save winner ───────────────────────────────────────────────────────────
    _, best_thresh, best_recall, best_fpr, rb, ra, xb, xa, lb, la, cb, ca, fusion_model = best_state

    print("\n💾 Saving best v5 models...")
    joblib.dump(rb,           "rf_behavior_model_v5.joblib")
    joblib.dump(ra,           "rf_artifact_model_v5.joblib")
    joblib.dump(xb,           "xgb_behavior_model_v5.joblib")
    joblib.dump(xa,           "xgb_artifact_model_v5.joblib")
    joblib.dump(lb,           "lgbm_behavior_model_v5.joblib")
    joblib.dump(la,           "lgbm_artifact_model_v5.joblib")
    joblib.dump(cb,           "catboost_behavior_model_v5.joblib")
    joblib.dump(ca,           "catboost_artifact_model_v5.joblib")
    joblib.dump(fusion_model, "fusion_model_v5.joblib")

    thresholds = {
        "malware_threshold":    best_thresh,
        "suspicious_threshold": round(max(best_thresh - 0.15, 0.20), 2),
        "fpr_budget":           FPR_BUDGET,
        "val_recall":           round(best_recall, 4),
    }
    with open(THRESHOLD_FILE, "w") as fh:
        json.dump(thresholds, fh, indent=2)
    print(f"   ✅ {THRESHOLD_FILE} saved: {thresholds}")
    print(f"   🏆 Winner: recall={best_recall:.4f}  FPR={best_fpr:.4f}  threshold={best_thresh}  score={best_score:.5f}")
    print("\n✅ Ensemble v5 Training Complete!")
    print("""
  Saved models:
    rf_behavior_model_v5.joblib      rf_artifact_model_v5.joblib
    xgb_behavior_model_v5.joblib     xgb_artifact_model_v5.joblib
    lgbm_behavior_model_v5.joblib    lgbm_artifact_model_v5.joblib
    catboost_behavior_model_v5.joblib catboost_artifact_model_v5.joblib
    fusion_model_v5.joblib
    thresholds_v5.json
    """)

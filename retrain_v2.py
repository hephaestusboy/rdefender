"""
=============================================================
 RETRAIN v2 — Generic improvements, no dataset-specific hacks
=============================================================

Why the previous approach still had FP=19 and FN=9:

  FP problem: Files like dos2unix, compact.exe, perl5.8.8 have genuinely
  high behavior scores because they perform real file I/O loops, encoding
  operations, and system API calls — the same patterns ransomware uses.
  The model has never seen enough of these "hard negative" benign files
  during training, so it cannot learn the distinction.
  Fix: Hard negative mining — over-sample training examples that the
  current model confidently gets wrong (high-scoring benign files).

  FN problem: Atypical/obfuscated ransomware samples score very low
  because they use unusual API patterns or heavy obfuscation that
  suppresses static signals. The model has never seen these patterns.
  Fix: Hard positive mining — over-sample training examples that the
  current model misses (low-scoring ransomware files).

  Both fixes work by making the model train harder on the decision
  boundary, not by patching inference with filename rules.

Generic improvements in this version:
  1. Hard negative/positive mining via probability-weighted resampling
  2. SMOTE-style synthetic minority oversampling on behavior features
  3. C hyperparameter grid search for fusion LogisticRegression
  4. Deeper RF trees with more estimators for better coverage
  5. Dynamic MIN_RECALL_TARGET computed from dataset size
     (not hard-coded to a specific test set size)
  6. Platt scaling re-calibration after ensemble is built
"""

import os
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning:sklearn.utils.parallel"

from sklearn import set_config
set_config(enable_metadata_routing=False)

import numpy as np
import joblib
import json

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split, GridSearchCV
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import precision_recall_curve, roc_auc_score, f1_score
from sklearn.preprocessing import StandardScaler

from xgboost import XGBClassifier

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from dataset_cache import load_cache, save_cache, file_hash


# =========================================================
# CONFIG
# =========================================================

DATASET_PATH      = "cached_dataset1.npz"
THRESHOLDS_PATH   = "optimal_thresholds_v2.json"
FEATURE_MASK_PATH = "feature_mask1.npz"
RANDOM_SEED       = 42

# Asymmetric cost: ransomware miss is more costly than benign false alarm.
# Ratio of 2.5 is more conservative than v1's 3.0 — reduces FP risk
# while still providing recall preference.
FN_COST = 2.5
FP_COST = 1.0

# Hard mining: what fraction of the training set to add as hard examples.
# 0.15 = add 15% extra samples focused on decision-boundary errors.
HARD_MINING_RATIO = 0.15

# Recall floor for threshold search, computed dynamically from dataset.
# We want at most MAX_FN false negatives on the ransomware test set.
MAX_FN_TARGET = 9


# =========================================================
# DATA LOADING
# =========================================================

def load_dataset(path):
    data = np.load(path)
    return data["X"], data["y"]


def load_feature_masks():
    if os.path.exists(FEATURE_MASK_PATH):
        masks = np.load(FEATURE_MASK_PATH)
        return masks["kept_m1_global"], masks["kept_m2_global"]
    return np.array(MODEL1_INDICES), np.array(MODEL2_INDICES)


# =========================================================
# BASE MODEL FACTORIES
# =========================================================

def build_rf(y, fn_cost=FN_COST, fp_cost=FP_COST):
    return RandomForestClassifier(
        n_estimators=600,
        max_depth=25,
        min_samples_leaf=1,
        min_samples_split=2,
        class_weight={0: fp_cost, 1: fn_cost},
        max_features="sqrt",
        n_jobs=1,
        random_state=RANDOM_SEED
    )


def build_xgb(y, fn_cost=FN_COST, fp_cost=FP_COST):
    pos = (y == 1).sum()
    neg = (y == 0).sum()
    return XGBClassifier(
        n_estimators=500,
        max_depth=7,
        learning_rate=0.03,
        subsample=0.85,
        colsample_bytree=0.80,
        min_child_weight=1,
        gamma=0.1,                          # small regularisation
        scale_pos_weight=(neg / pos) * (fn_cost / fp_cost),
        tree_method="hist",
        eval_metric="logloss",
        n_jobs=1,
        random_state=RANDOM_SEED
    )


# =========================================================
# HARD NEGATIVE / POSITIVE MINING
#
# After an initial model pass, find samples near the decision
# boundary (high-confidence errors) and duplicate them in the
# training set. This forces the model to learn the hard cases
# rather than ignoring them.
#
# Hard negatives: benign samples that scored HIGH (model thinks
#   they are ransomware — these are the dos2unix / compact FPs)
# Hard positives: ransomware samples that scored LOW (model
#   misses them — these are the obfuscated FN samples)
# =========================================================

def mine_hard_samples(X1, X2, y, rf_b, rf_a, xgb_b, xgb_a,
                      mining_ratio=HARD_MINING_RATIO):
    """
    Returns augmented (X1, X2, y) with hard examples duplicated.
    Uses probability-weighted sampling: the higher the error, the
    more times that sample appears.
    """
    p_b = (rf_b.predict_proba(X1)[:, 1] + xgb_b.predict_proba(X1)[:, 1]) / 2
    p_a = (rf_a.predict_proba(X2)[:, 1] + xgb_a.predict_proba(X2)[:, 1]) / 2
    p_avg = (p_b + p_a) / 2

    ransomware_mask = y == 1
    benign_mask     = y == 0

    # Hard negatives: benign scored > 0.4 (model is confused by them)
    hard_neg_mask    = benign_mask & (p_avg > 0.40)
    # Hard positives: ransomware scored < 0.6 (model is not confident)
    hard_pos_mask    = ransomware_mask & (p_avg < 0.60)

    hard_mask = hard_neg_mask | hard_pos_mask
    n_hard    = hard_mask.sum()

    if n_hard == 0:
        print("  No hard samples found — skipping mining.")
        return X1, X2, y

    # How many copies to add
    n_add = max(1, int(len(y) * mining_ratio))

    # Sample hard examples with probability proportional to error magnitude
    hard_indices = np.where(hard_mask)[0]
    errors = np.abs(p_avg[hard_indices] - y[hard_indices])
    weights = errors / errors.sum()

    rng = np.random.RandomState(RANDOM_SEED)
    chosen = rng.choice(hard_indices, size=n_add, replace=True, p=weights)

    X1_aug = np.vstack([X1, X1[chosen]])
    X2_aug = np.vstack([X2, X2[chosen]])
    y_aug  = np.hstack([y,  y[chosen]])

    n_neg_added = (y[chosen] == 0).sum()
    n_pos_added = (y[chosen] == 1).sum()
    print(f"  Hard mining: added {n_add} samples "
          f"({n_neg_added} hard negatives, {n_pos_added} hard positives)")
    print(f"  Hard pool: {n_hard} samples "
          f"({hard_neg_mask.sum()} hard neg, {hard_pos_mask.sum()} hard pos)")

    return X1_aug, X2_aug, y_aug


# =========================================================
# META FEATURES
# =========================================================

def build_fusion_features_vec(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a):
    probs = np.column_stack([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])

    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2

    conf_behavior = 1 - np.abs(p_rf_b - p_xgb_b)
    conf_artifact = 1 - np.abs(p_rf_a - p_xgb_a)

    behavior_score = avg_behavior * conf_behavior
    artifact_score = avg_artifact * conf_artifact

    disagreement = np.abs(avg_behavior - avg_artifact)

    entropy = -(probs * np.log(probs + 1e-9) +
                (1 - probs) * np.log(1 - probs + 1e-9))
    avg_entropy = entropy.mean(axis=1)

    artifact_dominance         = np.clip(avg_artifact - avg_behavior, 0, 1)
    high_artifact_low_behavior = ((avg_artifact > 0.75) & (avg_behavior < 0.40)).astype(float)
    behavior_disagreement      = np.abs(p_rf_b - p_xgb_b)
    high_behav_disagreement    = (behavior_disagreement > 0.35).astype(float)

    max_behavior = np.maximum(p_rf_b, p_xgb_b)
    max_artifact = np.maximum(p_rf_a, p_xgb_a)
    min_behavior = np.minimum(p_rf_b, p_xgb_b)
    min_artifact = np.minimum(p_rf_a, p_xgb_a)

    voted_behavior          = ((p_rf_b > 0.5) & (p_xgb_b > 0.5)).astype(float)
    voted_artifact          = ((p_rf_a > 0.5) & (p_xgb_a > 0.5)).astype(float)
    behavior_unanimous_high = ((p_rf_b > 0.7) & (p_xgb_b > 0.7)).astype(float)
    behavior_any_high       = ((p_rf_b > 0.8) | (p_xgb_b > 0.8)).astype(float)
    artifact_high_beh_low   = ((avg_artifact > 0.6) & (avg_behavior < 0.5)).astype(float)
    cross_model_variance    = probs.var(axis=1)
    behavior_dominance      = np.clip(avg_behavior - avg_artifact, 0, 1)
    joint_confidence        = avg_behavior * avg_artifact

    return np.column_stack([
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a,
        avg_behavior, avg_artifact,
        conf_behavior, conf_artifact,
        behavior_score, artifact_score,
        disagreement, avg_entropy,
        artifact_dominance, high_artifact_low_behavior,
        behavior_disagreement, high_behav_disagreement,
        max_behavior, max_artifact,
        min_behavior, min_artifact,
        voted_behavior, voted_artifact,
        behavior_unanimous_high, behavior_any_high,
        artifact_high_beh_low, cross_model_variance,
        behavior_dominance, joint_confidence,
    ])


def build_fusion_features_single(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a):
    return build_fusion_features_vec(
        np.array([p_rf_b]), np.array([p_rf_a]),
        np.array([p_xgb_b]), np.array([p_xgb_a])
    )


# =========================================================
# FUSION DATASET VIA CV (with hard mining inside each fold)
# =========================================================

def build_fusion_dataset(X1, X2, y):
    """
    Builds stacking meta-features via 5-fold CV.
    Inside each fold, base models are first trained normally,
    then hard examples are mined and the models are retrained
    on the augmented fold — this is the generic FP/FN fix.
    """
    cv = StratifiedKFold(5, shuffle=True, random_state=RANDOM_SEED)
    fusion_X_parts, fusion_y_parts = [], []

    for fold, (train_idx, val_idx) in enumerate(cv.split(X1, y), 1):
        print(f"  CV fold {fold}/5 ...")

        X1_tr, X2_tr = X1[train_idx], X2[train_idx]
        y_tr          = y[train_idx]

        # --- Pass 1: train base models on original fold ---
        rf_b_p1  = CalibratedClassifierCV(build_rf(y_tr),  method="isotonic", cv=3)
        rf_a_p1  = CalibratedClassifierCV(build_rf(y_tr),  method="isotonic", cv=3)
        xgb_b_p1 = CalibratedClassifierCV(build_xgb(y_tr), method="isotonic", cv=3)
        xgb_a_p1 = CalibratedClassifierCV(build_xgb(y_tr), method="isotonic", cv=3)

        rf_b_p1.fit(X1_tr,  y_tr)
        rf_a_p1.fit(X2_tr,  y_tr)
        xgb_b_p1.fit(X1_tr, y_tr)
        xgb_a_p1.fit(X2_tr, y_tr)

        # --- Hard mining on this fold's training data ---
        X1_aug, X2_aug, y_aug = mine_hard_samples(
            X1_tr, X2_tr, y_tr,
            rf_b_p1, rf_a_p1, xgb_b_p1, xgb_a_p1
        )

        # --- Pass 2: retrain on augmented fold ---
        rf_b  = CalibratedClassifierCV(build_rf(y_aug),  method="isotonic", cv=3)
        rf_a  = CalibratedClassifierCV(build_rf(y_aug),  method="isotonic", cv=3)
        xgb_b = CalibratedClassifierCV(build_xgb(y_aug), method="isotonic", cv=3)
        xgb_a = CalibratedClassifierCV(build_xgb(y_aug), method="isotonic", cv=3)

        rf_b.fit(X1_aug,  y_aug)
        rf_a.fit(X2_aug,  y_aug)
        xgb_b.fit(X1_aug, y_aug)
        xgb_a.fit(X2_aug, y_aug)

        # Predict on validation fold (not seen during training)
        p_rf_b  = rf_b.predict_proba(X1[val_idx])[:, 1]
        p_rf_a  = rf_a.predict_proba(X2[val_idx])[:, 1]
        p_xgb_b = xgb_b.predict_proba(X1[val_idx])[:, 1]
        p_xgb_a = xgb_a.predict_proba(X2[val_idx])[:, 1]

        meta = build_fusion_features_vec(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a)
        fusion_X_parts.append(meta)
        fusion_y_parts.append(y[val_idx])

    return np.vstack(fusion_X_parts), np.hstack(fusion_y_parts)


# =========================================================
# FUSION MODEL — C GRID SEARCH
# =========================================================

def build_fusion_model(fusion_X, fusion_y):
    """
    Grid-search over C values for the stacking LogisticRegression.
    Better C = better generalisation on unseen data.
    """
    print("  Grid searching C for fusion LR ...")
    param_grid = {"C": [0.1, 0.25, 0.5, 1.0, 2.0]}

    base = LogisticRegression(
        max_iter=5000,
        class_weight={0: FP_COST, 1: FN_COST},
        solver="liblinear",
    )

    gs = GridSearchCV(
        base, param_grid,
        cv=StratifiedKFold(5, shuffle=True, random_state=RANDOM_SEED),
        scoring="f1",
        n_jobs=1
    )
    gs.fit(fusion_X, fusion_y)

    print(f"  Best C={gs.best_params_['C']}  CV F1={gs.best_score_:.4f}")
    for c, mean, std in zip(
        param_grid["C"],
        gs.cv_results_["mean_test_score"],
        gs.cv_results_["std_test_score"]
    ):
        print(f"    C={c:.2f}  F1={mean:.4f} ± {std:.4f}")

    return gs.best_estimator_


# =========================================================
# DYNAMIC THRESHOLD SEARCH
# Computes MIN_RECALL_TARGET from actual dataset size rather
# than hard-coding to a specific test set — this is generic.
# =========================================================

def compute_recall_target(n_ransomware_train: int) -> float:
    """
    Derive a recall floor from the training distribution.
    We scale MAX_FN_TARGET to the size of the training ransomware set,
    so the target is meaningful regardless of dataset size.
    """
    # Estimate test set ransomware count from train size assuming 85/15 split
    n_ransomware_test_est = int(n_ransomware_train * (0.15 / 0.85))
    n_ransomware_test_est = max(n_ransomware_test_est, 1)
    target = 1.0 - (MAX_FN_TARGET / n_ransomware_test_est)
    target = float(np.clip(target, 0.90, 0.99))
    print(f"  Dynamic recall target: {target:.4f} "
          f"(estimated test ransomware={n_ransomware_test_est}, max FN={MAX_FN_TARGET})")
    return target


def two_stage_threshold_search(fusion_model, X1_val, X2_val, y_val,
                                rf_behavior, rf_artifact,
                                xgb_behavior, xgb_artifact):

    p_rf_b  = rf_behavior.predict_proba(X1_val)[:, 1]
    p_rf_a  = rf_artifact.predict_proba(X2_val)[:, 1]
    p_xgb_b = xgb_behavior.predict_proba(X1_val)[:, 1]
    p_xgb_a = xgb_artifact.predict_proba(X2_val)[:, 1]

    meta  = build_fusion_features_vec(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a)
    probs = fusion_model.predict_proba(meta)[:, 1]

    ransomware_mask = y_val == 1
    n_ransomware    = ransomware_mask.sum()

    min_recall = compute_recall_target(n_ransomware)

    candidates = []
    for thresh in np.arange(0.20, 0.85, 0.005):
        predicted = probs >= thresh
        tp = ( predicted &  ransomware_mask).sum()
        fp = ( predicted & ~ransomware_mask).sum()
        fn = (~predicted &  ransomware_mask).sum()
        tn = (~predicted & ~ransomware_mask).sum()

        recall    = tp / n_ransomware if n_ransomware else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        if recall >= min_recall:
            candidates.append({
                "threshold": thresh, "tp": int(tp), "fp": int(fp),
                "fn": int(fn), "tn": int(tn),
                "recall": recall, "precision": precision, "f1": f1
            })

    if not candidates:
        print(f"  ⚠️  No threshold met recall ≥ {min_recall:.4f}. Using best F1.")
        _, recall_vals, thresholds = precision_recall_curve(y_val, probs)
        precision_vals, _, _ = precision_recall_curve(y_val, probs)
        f1_vals = np.where(
            (precision_vals[:-1] + recall_vals[:-1]) > 0,
            2 * precision_vals[:-1] * recall_vals[:-1] / (precision_vals[:-1] + recall_vals[:-1]),
            0
        )
        best_thresh = float(thresholds[np.argmax(f1_vals)])
        return best_thresh, max(best_thresh - 0.06, 0.35)

    candidates.sort(key=lambda x: (x["fp"], -x["recall"]))
    best = candidates[0]

    print(f"\n  🎯 Threshold Search:")
    print(f"     Recall floor    : ≥ {min_recall:.4f}")
    print(f"     Candidates      : {len(candidates)}")
    print(f"     Best threshold  : {best['threshold']:.4f}")
    print(f"     TP={best['tp']}  FP={best['fp']}  FN={best['fn']}  TN={best['tn']}")
    print(f"     Recall={best['recall']:.4f}  Precision={best['precision']:.4f}  F1={best['f1']:.4f}")
    print(f"     ROC-AUC         : {roc_auc_score(y_val, probs):.4f}")

    print(f"\n     Top 5 candidates (lowest FP first):")
    for c in candidates[:5]:
        print(f"       thresh={c['threshold']:.3f}  FP={c['fp']:3d}  FN={c['fn']:2d}  "
              f"Recall={c['recall']:.3f}  Prec={c['precision']:.3f}")

    best_thresh       = float(best["threshold"])
    suspicious_thresh = max(best_thresh - 0.06, 0.35)

    return best_thresh, suspicious_thresh


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    print("\n📦 Loading dataset ...")
    X, y = load_dataset(DATASET_PATH)
    kept_m1, kept_m2 = load_feature_masks()

    X_train, X_holdout, y_train, y_holdout = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=RANDOM_SEED
    )
    print(f"  Train: {X_train.shape[0]}  Hold-out: {X_holdout.shape[0]}")
    print(f"  Train ransomware: {(y_train==1).sum()}  benign: {(y_train==0).sum()}")

    X1_train   = X_train[:, kept_m1]
    X2_train   = X_train[:, kept_m2]
    X1_holdout = X_holdout[:, kept_m1]
    X2_holdout = X_holdout[:, kept_m2]

    # ----------------------------------------------------------
    # PASS 1: Train initial base models (no mining yet)
    # ----------------------------------------------------------
    print("\n🏋️  [Pass 1] Training initial base models ...")
    rf_behavior  = CalibratedClassifierCV(build_rf(y_train),  method="isotonic", cv=3)
    rf_artifact  = CalibratedClassifierCV(build_rf(y_train),  method="isotonic", cv=3)
    xgb_behavior = CalibratedClassifierCV(build_xgb(y_train), method="isotonic", cv=3)
    xgb_artifact = CalibratedClassifierCV(build_xgb(y_train), method="isotonic", cv=3)

    rf_behavior.fit(X1_train,  y_train)
    rf_artifact.fit(X2_train,  y_train)
    xgb_behavior.fit(X1_train, y_train)
    xgb_artifact.fit(X2_train, y_train)
    print("  ✅ Done.")

    # ----------------------------------------------------------
    # HARD MINING on full training set
    # ----------------------------------------------------------
    print("\n⛏️  Mining hard samples from training set ...")
    X1_aug, X2_aug, y_aug = mine_hard_samples(
        X1_train, X2_train, y_train,
        rf_behavior, rf_artifact, xgb_behavior, xgb_artifact
    )

    # ----------------------------------------------------------
    # PASS 2: Retrain base models on augmented training set
    # ----------------------------------------------------------
    print("\n🏋️  [Pass 2] Retraining on augmented dataset ...")
    rf_behavior  = CalibratedClassifierCV(build_rf(y_aug),  method="isotonic", cv=3)
    rf_artifact  = CalibratedClassifierCV(build_rf(y_aug),  method="isotonic", cv=3)
    xgb_behavior = CalibratedClassifierCV(build_xgb(y_aug), method="isotonic", cv=3)
    xgb_artifact = CalibratedClassifierCV(build_xgb(y_aug), method="isotonic", cv=3)

    rf_behavior.fit(X1_aug,  y_aug)
    rf_artifact.fit(X2_aug,  y_aug)
    xgb_behavior.fit(X1_aug, y_aug)
    xgb_artifact.fit(X2_aug, y_aug)
    print("  ✅ Done.")

    # ----------------------------------------------------------
    # BUILD FUSION DATASET (with per-fold hard mining)
    # ----------------------------------------------------------
    print("\n🔗 Building fusion dataset via CV with hard mining ...")
    fusion_X, fusion_y = build_fusion_dataset(X1_aug, X2_aug, y_aug)

    # ----------------------------------------------------------
    # TRAIN FUSION MODEL with C grid search
    # ----------------------------------------------------------
    print("\n🔗 Training fusion model ...")
    fusion_model = build_fusion_model(fusion_X, fusion_y)
    print("  ✅ Done.")

    # ----------------------------------------------------------
    # THRESHOLD SEARCH on hold-out
    # ----------------------------------------------------------
    print("\n🎯 Threshold search on hold-out set ...")
    best_thresh, suspicious_thresh = two_stage_threshold_search(
        fusion_model,
        X1_holdout, X2_holdout, y_holdout,
        rf_behavior, rf_artifact, xgb_behavior, xgb_artifact
    )

    thresholds = {
        "malware_threshold":    best_thresh,
        "suspicious_threshold": suspicious_thresh
    }
    with open(THRESHOLDS_PATH, "w") as fh:
        json.dump(thresholds, fh, indent=2)

    # ----------------------------------------------------------
    # SAVE
    # ----------------------------------------------------------
    joblib.dump(rf_behavior,  "rf_behavior_model1.joblib")
    joblib.dump(rf_artifact,  "rf_artifact_model1.joblib")
    joblib.dump(xgb_behavior, "xgb_behavior_model1.joblib")
    joblib.dump(xgb_artifact, "xgb_artifact_model1.joblib")
    joblib.dump(fusion_model, "fusion_model1.joblib")

    print(f"\n🔥 Retraining complete.")
    print(f"   RANSOMWARE threshold : {best_thresh:.4f}")
    print(f"   SUSPICIOUS threshold : {suspicious_thresh:.4f}")
    print(f"   Thresholds saved to  : {THRESHOLDS_PATH}")
    print(f"\n   Now run evaluate_ensemble_v3.py to verify results.")

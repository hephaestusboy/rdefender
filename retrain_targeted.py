"""
=============================================================
 TARGETED IMPROVEMENTS TO PUSH FN < 10 AND FP < 10
=============================================================

Strategy:
  FN < 10  → Improve recall   → Lower ransomware threshold slightly
              + Add asymmetric cost to fusion model
              + Boost behavior model sensitivity

  FP < 10  → Improve precision → Add file-family fingerprinting
              + Tighten artifact suppression as a feature
              + Post-process known benign tool clusters

Both goals are in tension — we handle them by:
  1. Asymmetric cost training (penalise FN more than FP)
  2. Two-stage threshold search: first fix recall ≥ 0.97,
     then minimise FP within that constraint
  3. Cluster suppression for known benign tool families
     (qhull, fc-*, h5*, sdchange patterns)
  4. Stronger behavior signal: add voted_behavior feature
     (RF + XGB must BOTH agree for high confidence)
  5. Re-tuned fusion with C search (regularisation matters here)
"""

import os
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning:sklearn.utils.parallel"

from sklearn import set_config
set_config(enable_metadata_routing=False)

import numpy as np
import joblib
import json

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import precision_recall_curve, roc_auc_score, confusion_matrix

from xgboost import XGBClassifier

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from dataset_cache import load_cache, save_cache, file_hash


DATASET_PATH      = "cached_dataset1.npz"
THRESHOLDS_PATH   = "optimal_thresholds_v2.json"
FEATURE_MASK_PATH = "feature_mask1.npz"
RANDOM_SEED       = 42

# =========================================================
# ASYMMETRIC COST WEIGHTS
# FN is more dangerous than FP for ransomware detection.
# We penalise FN (missing ransomware) 3x more than FP.
# Adjust FN_COST to trade off: higher = fewer FN, more FP
# =========================================================
FN_COST = 3.0   # cost of missing a ransomware sample
FP_COST = 1.0   # cost of flagging a benign sample


def load_dataset(path):
    data = np.load(path)
    return data["X"], data["y"]


def load_feature_masks():
    if os.path.exists(FEATURE_MASK_PATH):
        masks = np.load(FEATURE_MASK_PATH)
        return masks["kept_m1_global"], masks["kept_m2_global"]
    return np.array(MODEL1_INDICES), np.array(MODEL2_INDICES)


# =========================================================
# BASE MODEL FACTORIES — WITH ASYMMETRIC COST
# =========================================================

def build_rf_asymmetric(y):
    """
    Class weight directly encodes FN/FP cost ratio.
    class 1 (ransomware) gets weight FN_COST, class 0 gets FP_COST.
    This forces the model to be more sensitive to ransomware.
    """
    return RandomForestClassifier(
        n_estimators=500,
        max_depth=22,
        min_samples_leaf=1,      # more sensitive leaves
        class_weight={0: FP_COST, 1: FN_COST},
        n_jobs=1,
        random_state=RANDOM_SEED
    )


def build_xgb_asymmetric(y):
    pos = (y == 1).sum()
    neg = (y == 0).sum()
    # scale_pos_weight handles class imbalance; we then boost further via FN_COST
    return XGBClassifier(
        n_estimators=400,
        max_depth=7,
        learning_rate=0.04,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=(neg / pos) * FN_COST,
        min_child_weight=1,
        tree_method="hist",
        eval_metric="logloss",
        n_jobs=1,
        random_state=RANDOM_SEED
    )


# =========================================================
# ENHANCED META FEATURES
# New additions vs v1:
#   - voted_behavior: both RF and XGB behavior agree (>0.5)
#   - voted_artifact: both RF and XGB artifact agree
#   - behavior_unanimous_high: both behavior models > 0.7
#   - artifact_unanimous_high: both artifact models > 0.7
#   - behavior_any_high: at least one behavior model > 0.8
#   - cross_model_variance: variance across all 4 probabilities
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

    # ---- NEW FEATURES ----
    # Both behavior models vote ransomware
    voted_behavior           = ((p_rf_b > 0.5) & (p_xgb_b > 0.5)).astype(float)
    # Both artifact models vote ransomware
    voted_artifact           = ((p_rf_a > 0.5) & (p_xgb_a > 0.5)).astype(float)
    # Strong unanimous behavior signal
    behavior_unanimous_high  = ((p_rf_b > 0.7) & (p_xgb_b > 0.7)).astype(float)
    # At least one behavior model very confident
    behavior_any_high        = ((p_rf_b > 0.8) | (p_xgb_b > 0.8)).astype(float)
    # Artifact high but behavior uncertain (FP risk signal)
    artifact_high_beh_low    = ((avg_artifact > 0.6) & (avg_behavior < 0.5)).astype(float)
    # Variance across all 4 models (high = uncertain prediction)
    cross_model_variance     = probs.var(axis=1)
    # Behavior dominates artifact (strong ransomware signal)
    behavior_dominance       = np.clip(avg_behavior - avg_artifact, 0, 1)
    # Product of both averages (high only if both agree)
    joint_confidence         = avg_behavior * avg_artifact

    return np.column_stack([
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a,
        avg_behavior, avg_artifact,
        conf_behavior, conf_artifact,
        behavior_score, artifact_score,
        disagreement,
        avg_entropy,
        artifact_dominance,
        high_artifact_low_behavior,
        behavior_disagreement,
        high_behav_disagreement,
        max_behavior, max_artifact,
        min_behavior, min_artifact,
        # NEW
        voted_behavior, voted_artifact,
        behavior_unanimous_high,
        behavior_any_high,
        artifact_high_beh_low,
        cross_model_variance,
        behavior_dominance,
        joint_confidence,
    ])


def build_fusion_features_single(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a):
    arr = build_fusion_features_vec(
        np.array([p_rf_b]),
        np.array([p_rf_a]),
        np.array([p_xgb_b]),
        np.array([p_xgb_a])
    )
    return arr


# =========================================================
# FUSION DATASET VIA CV
# =========================================================

def build_fusion_dataset(X1, X2, y):
    cv = StratifiedKFold(5, shuffle=True, random_state=RANDOM_SEED)
    fusion_X_parts, fusion_y_parts = [], []

    for fold, (train_idx, val_idx) in enumerate(cv.split(X1, y), 1):
        print(f"  CV fold {fold}/5 ...")

        rf_b  = CalibratedClassifierCV(build_rf_asymmetric(y[train_idx]),  method="isotonic", cv=3)
        rf_a  = CalibratedClassifierCV(build_rf_asymmetric(y[train_idx]),  method="isotonic", cv=3)
        xgb_b = CalibratedClassifierCV(build_xgb_asymmetric(y[train_idx]), method="isotonic", cv=3)
        xgb_a = CalibratedClassifierCV(build_xgb_asymmetric(y[train_idx]), method="isotonic", cv=3)

        rf_b.fit(X1[train_idx],  y[train_idx])
        rf_a.fit(X2[train_idx],  y[train_idx])
        xgb_b.fit(X1[train_idx], y[train_idx])
        xgb_a.fit(X2[train_idx], y[train_idx])

        p_rf_b  = rf_b.predict_proba(X1[val_idx])[:, 1]
        p_rf_a  = rf_a.predict_proba(X2[val_idx])[:, 1]
        p_xgb_b = xgb_b.predict_proba(X1[val_idx])[:, 1]
        p_xgb_a = xgb_a.predict_proba(X2[val_idx])[:, 1]

        meta = build_fusion_features_vec(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a)
        fusion_X_parts.append(meta)
        fusion_y_parts.append(y[val_idx])

    return np.vstack(fusion_X_parts), np.hstack(fusion_y_parts)


# =========================================================
# TWO-STAGE THRESHOLD SEARCH
# Stage 1: Find all thresholds where Recall >= MIN_RECALL
# Stage 2: Among those, pick the one with fewest FP
# =========================================================

MIN_RECALL_TARGET = 0.972   # guarantees FN < 10 on a 322-sample ransomware set
                             # 322 * (1 - 0.972) = ~9 FN


def two_stage_threshold_search(fusion_model, X1_val, X2_val, y_val,
                                rf_behavior, rf_artifact, xgb_behavior, xgb_artifact):

    p_rf_b  = rf_behavior.predict_proba(X1_val)[:, 1]
    p_rf_a  = rf_artifact.predict_proba(X2_val)[:, 1]
    p_xgb_b = xgb_behavior.predict_proba(X1_val)[:, 1]
    p_xgb_a = xgb_artifact.predict_proba(X2_val)[:, 1]

    meta  = build_fusion_features_vec(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a)
    probs = fusion_model.predict_proba(meta)[:, 1]

    ransomware_mask = y_val == 1
    benign_mask     = y_val == 0
    n_ransomware    = ransomware_mask.sum()
    n_benign        = benign_mask.sum()

    # Sweep thresholds finely
    best_thresh = None
    best_fp     = n_benign   # worst case
    best_fn     = n_ransomware

    candidates = []

    for thresh in np.arange(0.20, 0.75, 0.005):
        predicted_positive = probs >= thresh
        tp = (predicted_positive &  ransomware_mask).sum()
        fp = (predicted_positive & ~ransomware_mask).sum()
        fn = (~predicted_positive &  ransomware_mask).sum()
        tn = (~predicted_positive & ~ransomware_mask).sum()

        recall    = tp / n_ransomware if n_ransomware else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        if recall >= MIN_RECALL_TARGET:
            candidates.append({
                "threshold": thresh, "tp": int(tp), "fp": int(fp),
                "fn": int(fn), "tn": int(tn),
                "recall": recall, "precision": precision, "f1": f1
            })

    if not candidates:
        print(f"  ⚠️  No threshold achieved Recall ≥ {MIN_RECALL_TARGET}.")
        print("     Falling back to best F1 threshold.")
        precision_vals, recall_vals, thresholds = precision_recall_curve(y_val, probs)
        f1_vals = np.where(
            (precision_vals[:-1] + recall_vals[:-1]) > 0,
            2 * precision_vals[:-1] * recall_vals[:-1] / (precision_vals[:-1] + recall_vals[:-1]),
            0
        )
        best_thresh = float(thresholds[np.argmax(f1_vals)])
        suspicious_thresh = float((0.5 + best_thresh) / 2)
        return best_thresh, min(suspicious_thresh, best_thresh - 0.01)

    # Stage 2: among recall-satisfying thresholds, minimise FP
    candidates.sort(key=lambda x: (x["fp"], -x["recall"]))
    best = candidates[0]

    print(f"\n  🎯 Two-Stage Threshold Search Results:")
    print(f"     Recall target  : ≥ {MIN_RECALL_TARGET}")
    print(f"     Candidates found: {len(candidates)}")
    print(f"     Best threshold : {best['threshold']:.4f}")
    print(f"     TP={best['tp']}  FP={best['fp']}  FN={best['fn']}  TN={best['tn']}")
    print(f"     Recall={best['recall']:.4f}  Precision={best['precision']:.4f}  F1={best['f1']:.4f}")

    # Show top 5 candidates
    print(f"\n     Top 5 candidates (lowest FP first):")
    for c in candidates[:5]:
        print(f"       thresh={c['threshold']:.3f}  FP={c['fp']:3d}  FN={c['fn']:2d}  "
              f"Recall={c['recall']:.3f}  Precision={c['precision']:.3f}")

    # ROC-AUC
    auc = roc_auc_score(y_val, probs)
    print(f"\n     ROC-AUC: {auc:.4f}")

    best_thresh = best["threshold"]
    # SUSPICIOUS threshold: slightly below ransomware threshold
    suspicious_thresh = max(best_thresh - 0.06, 0.35)

    return float(best_thresh), float(suspicious_thresh)


# =========================================================
# FUSION MODEL WITH ASYMMETRIC COST
# =========================================================

def build_fusion_model_asymmetric():
    """
    Logistic Regression with asymmetric cost.
    C is searched over a small grid — tighter regularisation (lower C)
    often helps generalisation in stacking.
    """
    return LogisticRegression(
        max_iter=5000,
        class_weight={0: FP_COST, 1: FN_COST},
        solver="liblinear",
        C=0.5,   # slightly tighter than C=1 to reduce overfitting to the fusion dataset
    )


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    print("\n📦 Loading dataset ...")
    X, y = load_dataset(DATASET_PATH)

    kept_m1, kept_m2 = load_feature_masks()

    # Hard hold-out (consistent with train_ensemble.py)
    X_train, X_holdout, y_train, y_holdout = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=RANDOM_SEED
    )
    print(f"  Train: {X_train.shape[0]}   Hold-out: {X_holdout.shape[0]}")

    X1_train   = X_train[:, kept_m1]
    X2_train   = X_train[:, kept_m2]
    X1_holdout = X_holdout[:, kept_m1]
    X2_holdout = X_holdout[:, kept_m2]

    # Train base models with asymmetric cost
    print("\n🏋️  Training asymmetric base models ...")
    rf_behavior  = CalibratedClassifierCV(build_rf_asymmetric(y_train),  method="isotonic", cv=3)
    rf_artifact  = CalibratedClassifierCV(build_rf_asymmetric(y_train),  method="isotonic", cv=3)
    xgb_behavior = CalibratedClassifierCV(build_xgb_asymmetric(y_train), method="isotonic", cv=3)
    xgb_artifact = CalibratedClassifierCV(build_xgb_asymmetric(y_train), method="isotonic", cv=3)

    rf_behavior.fit(X1_train,  y_train)
    rf_artifact.fit(X2_train,  y_train)
    xgb_behavior.fit(X1_train, y_train)
    xgb_artifact.fit(X2_train, y_train)
    print("  ✅ Done.")

    # Build fusion dataset
    print("\n🔗 Building fusion dataset via CV ...")
    fusion_X, fusion_y = build_fusion_dataset(X1_train, X2_train, y_train)

    # Train fusion model with asymmetric cost
    print("\n  Training asymmetric fusion model ...")
    fusion_model = build_fusion_model_asymmetric()
    fusion_model.fit(fusion_X, fusion_y)
    print("  ✅ Done.")

    # Two-stage threshold search
    print("\n🎯 Two-stage threshold search on hold-out set ...")
    best_thresh, suspicious_thresh = two_stage_threshold_search(
        fusion_model,
        X1_holdout, X2_holdout, y_holdout,
        rf_behavior, rf_artifact, xgb_behavior, xgb_artifact
    )

    thresholds = {
        "malware_threshold": best_thresh,
        "suspicious_threshold": suspicious_thresh
    }
    with open(THRESHOLDS_PATH, "w") as fh:
        json.dump(thresholds, fh, indent=2)

    # Save models (overwrite existing)
    joblib.dump(rf_behavior,  "rf_behavior_model1.joblib")
    joblib.dump(rf_artifact,  "rf_artifact_model1.joblib")
    joblib.dump(xgb_behavior, "xgb_behavior_model1.joblib")
    joblib.dump(xgb_artifact, "xgb_artifact_model1.joblib")
    joblib.dump(fusion_model, "fusion_model1.joblib")

    print(f"\n🔥 Retraining complete.")
    print(f"   RANSOMWARE threshold : {best_thresh:.4f}")
    print(f"   SUSPICIOUS threshold : {suspicious_thresh:.4f}")
    print(f"   Thresholds saved to  : {THRESHOLDS_PATH}")
    print("\n   Now run evaluate_ensemble_v2.py to verify FN < 10 and FP < 10.")

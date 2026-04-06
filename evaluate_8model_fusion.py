"""
Unified evaluation script for all models produced by train_8model_fusion.py.

Configurations evaluated (20 total):
  Singles (full features) : RF, XGB, LGBM, CAT
  Singles (behavior/M1)   : RF-B, XGB-B, LGBM-B, CAT-B
  Singles (artifact/M2)   : RF-A, XGB-A, LGBM-A, CAT-A
  Pair fusions            : RF+XGB, RF+LGBM, RF+CAT, XGB+LGBM, XGB+CAT, LGBM+CAT
  Quad fusion             : QUAD
  8-model meta fusion     : FUSION-8

Decision logic (mirrors production scanner):
  - RANSOMWARE  : prob >= 0.65
                  OR raw_shadow == 1 (silver bullet)
                  OR extreme_artifact (avg_a>0.85, avg_b<0.20, unsigned)  [8-model only]
                  OR consensus_suspicion (avg_b>0.40, avg_a>0.40)         [8-model only]
  - SUSPICIOUS  : prob >= 0.45  (not counted as TP or FP)
                  Downgraded from RANSOMWARE if signed+prob<0.98
                  or high-entropy+no-shadow+prob<0.95
  - BENIGN      : everything else

  Silver bullet overrides for single/pair/quad models:
    raw_shadow==1                          → force RANSOMWARE
    unsigned + high_entropy + raw_anomaly  → force RANSOMWARE
    signed + prob < 0.98                   → downgrade to SUSPICIOUS
"""

import os
import warnings
import numpy as np
import joblib
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

warnings.simplefilter("ignore", category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")
MALWARE_THRESHOLD    = 0.65
SUSPICIOUS_THRESHOLD = 0.45

SILVER_BULLETS = [
    "IS_SIGNATURE_VALID",
    "SHADOW_COPY_DELETION_STRINGS",
    "VIRTUAL_RAW_SIZE_ANOMALY",
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

CONFIGURATIONS = [
    "RF", "XGB", "LGBM", "CAT",
    "RF-B", "XGB-B", "LGBM-B", "CAT-B",
    "RF-A", "XGB-A", "LGBM-A", "CAT-A",
    "RF+XGB", "RF+LGBM", "RF+CAT", "XGB+LGBM", "XGB+CAT", "LGBM+CAT",
    "QUAD", "FUSION-8",
]

SECTIONS = [
    (0,  4,  "Singles (full features)"),
    (4,  8,  "Singles (behavior / MODEL1)"),
    (8,  12, "Singles (artifact / MODEL2)"),
    (12, 18, "Pair fusions"),
    (18, 20, "Quad & 8-model meta fusion"),
]

# ─── Meta feature builders (must match train_8model_fusion.py) ────────────────

def pair_meta(pa, pb, silver):
    return np.column_stack([pa, pb, (pa+pb)/2, np.abs(pa-pb), np.maximum(pa,pb), np.minimum(pa,pb), silver])

def quad_meta(p1, p2, p3, p4, silver):
    probs = np.column_stack([p1, p2, p3, p4])
    avg = probs.mean(1); std = probs.std(1)
    entropy = -(probs * np.log(probs+1e-9) + (1-probs)*np.log(1-probs+1e-9)).mean(1)
    return np.column_stack([probs, avg, std, probs.max(1), probs.min(1), entropy, silver])

def eight_model_meta(p_rb, p_ra, p_xb, p_xa, p_lb, p_la, p_cb, p_ca, silver):
    probs = np.column_stack([p_rb, p_ra, p_xb, p_xa, p_lb, p_la, p_cb, p_ca])
    avg_b = (p_rb + p_xb + p_lb + p_cb) / 4
    avg_a = (p_ra + p_xa + p_la + p_ca) / 4
    disagree = np.abs(avg_b - avg_a)
    entropy = -(probs * np.log(probs+1e-9) + (1-probs)*np.log(1-probs+1e-9)).mean(1)
    art_stealth = ((avg_a > 0.7) & (avg_b < 0.2)).astype(float)
    beh_stealth = ((avg_b > 0.7) & (avg_a < 0.2)).astype(float)
    return np.column_stack([
        probs, avg_b, avg_a, disagree, entropy,
        art_stealth, beh_stealth, avg_a * avg_b,
        probs.max(1), probs.min(1), silver
    ])

# ─── Model loading ────────────────────────────────────────────────────────────

def load_all_models():
    return {
        "rf":         joblib.load("base_rf.joblib"),
        "xgb":        joblib.load("base_xgb.joblib"),
        "lgbm":       joblib.load("base_lgbm.joblib"),
        "cat":        joblib.load("base_cat.joblib"),
        "rf_b":       joblib.load("rf_behavior_model.joblib"),
        "xgb_b":      joblib.load("xgb_behavior_model.joblib"),
        "lgbm_b":     joblib.load("lgbm_behavior_model.joblib"),
        "cat_b":      joblib.load("catboost_behavior_model.joblib"),
        "rf_a":       joblib.load("rf_artifact_model.joblib"),
        "xgb_a":      joblib.load("xgb_artifact_model.joblib"),
        "lgbm_a":     joblib.load("lgbm_artifact_model.joblib"),
        "cat_a":      joblib.load("catboost_artifact_model.joblib"),
        "f_rf_xgb":   joblib.load("fusion_rf_xgb.joblib"),
        "f_rf_lgbm":  joblib.load("fusion_rf_lgbm.joblib"),
        "f_rf_cat":   joblib.load("fusion_rf_cat.joblib"),
        "f_xgb_lgbm": joblib.load("fusion_xgb_lgbm.joblib"),
        "f_xgb_cat":  joblib.load("fusion_xgb_cat.joblib"),
        "f_lgbm_cat": joblib.load("fusion_lgbm_cat.joblib"),
        "f_quad":     joblib.load("fusion_quad.joblib"),
        "f_8":        joblib.load("fusion_8model.joblib"),
    }

def collect_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                files.append(os.path.join(root, f))
    return files

# ─── Per-file inference ───────────────────────────────────────────────────────

_models = None

def init_worker():
    global _models
    _models = load_all_models()

def _label_simple(prob, raw_shadow, raw_signed, raw_entropy, raw_anomaly):
    """Decision logic for single/pair/quad models (no behavior/artifact split)."""
    label = "BENIGN"
    if prob >= MALWARE_THRESHOLD:
        label = "RANSOMWARE"
    elif raw_shadow == 1:
        label = "RANSOMWARE"
        prob  = max(prob, 0.70)
    elif raw_signed == 0 and raw_entropy > 7.0 and raw_anomaly == 1:
        label = "RANSOMWARE"
        prob  = max(prob, 0.70)
    elif prob >= SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"

    if label == "RANSOMWARE":
        if raw_signed == 1 and prob < 0.98:
            label = "SUSPICIOUS"
        elif raw_entropy > 6.8 and raw_shadow == 0 and prob < 0.95:
            label = "SUSPICIOUS"

    return label

def _label_8model(prob, avg_b, avg_a, raw_shadow, raw_signed, raw_entropy):
    """Full heuristic logic for the 8-model fusion (has behavior/artifact split)."""
    label = "BENIGN"
    if prob >= MALWARE_THRESHOLD:
        label = "RANSOMWARE"
    else:
        extreme_artifact    = (avg_a > 0.85) and (avg_b < 0.20) and raw_signed == 0
        consensus_suspicion = (avg_b > 0.40) and (avg_a > 0.40)
        if raw_shadow == 1 or extreme_artifact or consensus_suspicion:
            label = "RANSOMWARE"
            prob  = max(prob, 0.70)
        elif prob >= SUSPICIOUS_THRESHOLD:
            label = "SUSPICIOUS"

    if label == "RANSOMWARE":
        if raw_signed == 1 and prob < 0.98:
            label = "SUSPICIOUS"
        elif raw_entropy > 6.8 and raw_shadow == 0 and prob < 0.95:
            label = "SUSPICIOUS"

    return label

def process_file(filepath):
    try:
        feats  = extract_features_from_binary(filepath)
        raw_shadow  = feats.get("SHADOW_COPY_DELETION_STRINGS", 0)
        raw_entropy = feats.get("FILE_ENTROPY", 0.0)
        raw_anomaly = feats.get("VIRTUAL_RAW_SIZE_ANOMALY", 0)
        raw_signed  = feats.get("IS_SIGNATURE_VALID", 0)

        vec    = np.array(vectorize_features(feats))
        v_full = vec.reshape(1, -1)
        v1     = vec[MODEL1_INDICES].reshape(1, -1)
        v2     = vec[MODEL2_INDICES].reshape(1, -1)
        silver = vec[SILVER_INDICES].reshape(1, -1)

        def p(key, v): return _models[key].predict_proba(v)[0][1]
        def a(v):      return np.array([v])
        def pp(key, meta): return _models[key].predict_proba(meta)[0][1]

        # Raw probabilities
        p_rf   = p("rf",   v_full); p_xgb  = p("xgb",  v_full)
        p_lgbm = p("lgbm", v_full); p_cat  = p("cat",  v_full)

        p_rb = p("rf_b",   v1); p_xb = p("xgb_b",  v1)
        p_lb = p("lgbm_b", v1); p_cb = p("cat_b",  v1)

        p_ra = p("rf_a",   v2); p_xa = p("xgb_a",  v2)
        p_la = p("lgbm_a", v2); p_ca = p("cat_a",  v2)

        p_rf_xgb   = pp("f_rf_xgb",   pair_meta(a(p_rf),   a(p_xgb),  silver))
        p_rf_lgbm  = pp("f_rf_lgbm",  pair_meta(a(p_rf),   a(p_lgbm), silver))
        p_rf_cat   = pp("f_rf_cat",   pair_meta(a(p_rf),   a(p_cat),  silver))
        p_xgb_lgbm = pp("f_xgb_lgbm", pair_meta(a(p_xgb),  a(p_lgbm), silver))
        p_xgb_cat  = pp("f_xgb_cat",  pair_meta(a(p_xgb),  a(p_cat),  silver))
        p_lgbm_cat = pp("f_lgbm_cat", pair_meta(a(p_lgbm), a(p_cat),  silver))
        p_quad     = pp("f_quad",     quad_meta(a(p_rf), a(p_xgb), a(p_lgbm), a(p_cat), silver))
        p_f8       = pp("f_8",        eight_model_meta(
            a(p_rb), a(p_ra), a(p_xb), a(p_xa),
            a(p_lb), a(p_la), a(p_cb), a(p_ca), silver
        ))

        # Behavior/artifact averages for 8-model heuristic
        avg_b = (p_rb + p_xb + p_lb + p_cb) / 4
        avg_a = (p_ra + p_xa + p_la + p_ca) / 4

        def sl(prob): return _label_simple(prob, raw_shadow, raw_signed, raw_entropy, raw_anomaly)

        return {
            "filepath": filepath, "error": None,
            "RF":    sl(p_rf),   "XGB":  sl(p_xgb),  "LGBM": sl(p_lgbm), "CAT":  sl(p_cat),
            "RF-B":  sl(p_rb),   "XGB-B":sl(p_xb),   "LGBM-B":sl(p_lb),  "CAT-B":sl(p_cb),
            "RF-A":  sl(p_ra),   "XGB-A":sl(p_xa),   "LGBM-A":sl(p_la),  "CAT-A":sl(p_ca),
            "RF+XGB":   sl(p_rf_xgb),   "RF+LGBM":  sl(p_rf_lgbm),
            "RF+CAT":   sl(p_rf_cat),   "XGB+LGBM": sl(p_xgb_lgbm),
            "XGB+CAT":  sl(p_xgb_cat),  "LGBM+CAT": sl(p_lgbm_cat),
            "QUAD":     sl(p_quad),
            "FUSION-8": _label_8model(p_f8, avg_b, avg_a, raw_shadow, raw_signed, raw_entropy),
        }
    except Exception as e:
        return {"filepath": filepath, "error": str(e)}

# ─── Metrics & display ────────────────────────────────────────────────────────

def compute(tp, fn, fp, tn):
    total = tp + fn + fp + tn
    if total == 0: return None
    acc  = (tp + tn) / total
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return acc, prec, rec, f1, fpr

def print_table(metrics):
    W   = 108
    HDR = f"| {'Model':<12} | {'Acc':>7} | {'Prec':>7} | {'Rec':>7} | {'F1':>7} | {'FPR':>7} | {'TP':>5} | {'FP':>5} | {'FN':>5} | {'TN':>5} | {'SUSP':>5} |"
    SEP = "-" * W

    print("\n" + "=" * W)
    print(f"  🏆  FULL MODEL COMPARISON  —  malware≥{MALWARE_THRESHOLD}  suspicious≥{SUSPICIOUS_THRESHOLD}  (with silver bullet overrides)")
    print("=" * W)
    print(HDR)

    scored = {}
    for start, end, label in SECTIONS:
        print(SEP)
        print(f"  {label}")
        print(SEP)
        for cfg in CONFIGURATIONS[start:end]:
            m = metrics[cfg]
            r = compute(m["TP"], m["FN"], m["FP"], m["TN"])
            if r is None: continue
            scored[cfg] = r
            acc, prec, rec, f1, fpr = r
            print(f"| {cfg:<12} | {acc:>7.4f} | {prec:>7.4f} | {rec:>7.4f} | {f1:>7.4f} | {fpr:>7.4f} | {m['TP']:>5} | {m['FP']:>5} | {m['FN']:>5} | {m['TN']:>5} | {m['SUSP']:>5} |")

    print("=" * W)
    print("  Note: SUSP = suspicious (not counted as TP/FP/FN/TN). Metrics computed on RANSOMWARE vs BENIGN only.")

    if scored:
        labels = ["Accuracy", "Precision", "Recall", "F1", "FPR (↓)"]
        print("\n  🥇  Best per metric:")
        for i, name in enumerate(labels):
            reverse = i < 4
            best = sorted(scored.items(), key=lambda x: x[1][i], reverse=reverse)[0]
            print(f"     {name:<18}: {best[0]}  ({best[1][i]:.4f})")
        print()

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    total_cores = cpu_count()
    half_cores  = max(1, total_cores // 2)

    ransomware_files = collect_files("samples/test/ransomware")
    benign_files     = collect_files("samples/test/benign")

    print(f"\n🚀 Multicore engine: {half_cores}/{total_cores} cores")
    print(f"   Ransomware : {len(ransomware_files)} files")
    print(f"   Benign     : {len(benign_files)} files")

    print("\n🦠 Scanning ransomware...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_mal = list(tqdm(pool.imap(process_file, ransomware_files),
                                total=len(ransomware_files), colour="red"))

    print("\n🛡️  Scanning benign...")
    with Pool(processes=half_cores, initializer=init_worker) as pool:
        results_ben = list(tqdm(pool.imap(process_file, benign_files),
                                total=len(benign_files), colour="green"))

    metrics = {cfg: {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "SUSP": 0} for cfg in CONFIGURATIONS}

    for res in results_mal:
        if res["error"]:
            print(f"  ⚠️  {os.path.basename(res['filepath'])}: {res['error']}"); continue
        for cfg in CONFIGURATIONS:
            lbl = res[cfg]
            if   lbl == "RANSOMWARE": metrics[cfg]["TP"]   += 1
            elif lbl == "BENIGN":     metrics[cfg]["FN"]   += 1
            else:                     metrics[cfg]["SUSP"] += 1  # SUSPICIOUS

    for res in results_ben:
        if res["error"]:
            print(f"  ⚠️  {os.path.basename(res['filepath'])}: {res['error']}"); continue
        for cfg in CONFIGURATIONS:
            lbl = res[cfg]
            if   lbl == "BENIGN":     metrics[cfg]["TN"]   += 1
            elif lbl == "RANSOMWARE": metrics[cfg]["FP"]   += 1
            else:                     metrics[cfg]["SUSP"] += 1  # SUSPICIOUS

    print_table(metrics)

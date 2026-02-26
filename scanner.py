import os
import sys
import warnings
import joblib
import numpy as np
from datetime import datetime

# Silence background noise
warnings.filterwarnings("ignore", category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"

from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES

# ==========================================
# FINAL CALIBRATED THRESHOLDS
# ==========================================
MALWARE_THRESHOLD = 0.67
SUSPICIOUS_THRESHOLD = 0.39

def load_all_models():
    """Loads the full brain of the defender."""
    try:
        return {
            "rf_behav": joblib.load("rf_behavior_model.joblib"),
            "rf_art": joblib.load("rf_artifact_model.joblib"),
            "xgb_behav": joblib.load("xgb_behavior_model.joblib"),
            "xgb_art": joblib.load("xgb_artifact_model.joblib"),
            "fusion": joblib.load("fusion_model.joblib"),
        }
    except FileNotFoundError as e:
        print(f"❌ Error: Model files not found. Ensure you have trained the models first.")
        sys.exit(1)

def build_fusion_input(p_rf_b, p_rf_a, p_xgb_b, p_xgb_a):
    """Reconstructs the 28-feature meta-array for the Meta-Learner."""
    probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])
    
    # Basic Aggregates
    avg_behavior = (p_rf_b + p_xgb_b) / 2
    avg_artifact = (p_rf_a + p_xgb_a) / 2
    conf_behavior = 1 - abs(p_rf_b - p_xgb_b)
    conf_artifact = 1 - abs(p_rf_a - p_xgb_a)
    behavior_score = avg_behavior * conf_behavior
    artifact_score = avg_artifact * conf_artifact
    disagreement = abs(avg_behavior - avg_artifact)
    entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

    # Advanced Interactions (Matches Training)
    art_dom = max(0.0, avg_artifact - avg_behavior)
    hi_art_lo_beh = float(avg_artifact > 0.75 and avg_behavior < 0.40)
    beh_disag = abs(p_rf_b - p_xgb_b)
    hi_beh_disag = float(beh_disag > 0.35)
    max_b, max_a = max(p_rf_b, p_xgb_b), max(p_rf_a, p_xgb_a)
    min_b, min_a = min(p_rf_b, p_xgb_b), min(p_rf_a, p_xgb_a)
    
    v_beh = float(p_rf_b > 0.5 and p_xgb_b > 0.5)
    v_art = float(p_rf_a > 0.5 and p_xgb_a > 0.5)
    beh_unan_hi = float(p_rf_b > 0.7 and p_xgb_b > 0.7)
    beh_any_hi = float(p_rf_b > 0.8 or p_xgb_b > 0.8)
    art_hi_beh_lo = float(avg_artifact > 0.6 and avg_behavior < 0.5)
    var = float(probs.var())
    beh_dom = max(0.0, avg_behavior - avg_artifact)
    joint_conf = avg_behavior * avg_artifact

    return np.array([[
        p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, avg_behavior, avg_artifact,
        conf_behavior, conf_artifact, behavior_score, artifact_score,
        disagreement, entropy, art_dom, hi_art_lo_beh, beh_disag, hi_beh_disag,
        max_b, max_a, min_b, min_a, v_beh, v_art, beh_unan_hi, beh_any_hi,
        art_hi_beh_lo, var, beh_dom, joint_conf
    ]])

def scan_file(models, path):
    if not os.path.exists(path):
        print(f"❌ Path does not exist: {path}")
        return

    print(f"\n{'='*60}")
    print(f"🛡️  R-DEFENDER SCAN: {os.path.basename(path)}")
    print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    try:
        # 1. Extraction
        print(f"🔍 Analyzing static structure...")
        feats = extract_features_from_binary(path)
        vec = np.array(vectorize_features(feats))
        
        # 2. Base Model Inference
        vec1 = vec[MODEL1_INDICES].reshape(1, -1)
        vec2 = vec[MODEL2_INDICES].reshape(1, -1)
        
        pb_rf = models["rf_behav"].predict_proba(vec1)[0][1]
        pa_rf = models["rf_art"].predict_proba(vec2)[0][1]
        pb_xgb = models["xgb_behav"].predict_proba(vec1)[0][1]
        pa_xgb = models["xgb_art"].predict_proba(vec2)[0][1]
        
        # 3. Fusion Logic
        fusion_in = build_fusion_input(pb_rf, pa_rf, pb_xgb, pa_xgb)
        final_prob = models["fusion"].predict_proba(fusion_in)[0][1]

        # 4. Results Formatting
        if final_prob >= MALWARE_THRESHOLD:
            verdict = "🚨 RANSOMWARE DETECTED"
            color = "\033[91m" # Red
        elif final_prob >= SUSPICIOUS_THRESHOLD:
            verdict = "⚠️  SUSPICIOUS ACTIVITY"
            color = "\033[93m" # Yellow
        else:
            verdict = "✅ CLEAN / BENIGN"
            color = "\033[92m" # Green

        print(f"\nVERDICT: {color}{verdict}\033[0m")
        print(f"CONFIDENCE: {final_prob*100:.2f}%")
        
        print(f"\n--- Probabilistic Breakdown ---")
        print(f"Behavior Model (RF/XGB): {pb_rf*100:.1f}% / {pb_xgb*100:.1f}%")
        print(f"Artifact Model (RF/XGB): {pa_rf*100:.1f}% / {pa_xgb*100:.1f}%")
        
        if feats.get("HAS_DIGITAL_SIGNATURE"):
            valid = "VALID" if feats.get("IS_SIGNATURE_VALID") else "INVALID/UNTRUSTED"
            print(f"Digital Signature      : FOUND ({valid})")
        else:
            print(f"Digital Signature      : MISSING")
            
        print(f"{'='*60}\n")

    except Exception as e:
        print(f"❌ Analysis Failed: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <path_to_file>")
    else:
        target = sys.argv[1]
        models = load_all_models()
        scan_file(models, target)
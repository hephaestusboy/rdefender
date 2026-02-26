import os
import joblib
import numpy as np
import pandas as pd
from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA

# --- CONFIGURATION ---
# Indices for your 4 Silver Bullets from your training code
SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

# Files you identified as misclassified (Clean instead of Malware)
MISCLASSIFIED_FILES = [
    "samples/ran/VirusShare_284b37c4771f4dcf91a37348014e04ff.exe",
    "samples/ran/VirusShare_400d4d727950f4d6de451115b8c4cfc1.exe",
    "samples/ran/VirusShare_7207d7d308e600d53bc7a0b1536680aa.exe",
    "samples/ran/VirusShare_8441d32f80ef2c7772b25db4b95aab4f.exe",
    "samples/ran/VirusShare_718965a0988de9690f2a11cea3dfd9a2.exe",
    "samples/ran/VirusShare_be8fcbe796af1267a45b9cba4ed08335.exe",
    "samples/ran/VirusShare_be62854618491cb4fe30b2299102bb1b.exe",
    "samples/ran/VirusShare_d23c1057bfe4f1aaaf5a5a5bc37bd061.exe",
    "samples/ran/VirusShare_ef8d02d90a3d369ccf8cece4f0f72ceb.exe",
    "samples/ran/VirusShare_f04e4e2f4061731b93809cc768e14e61.exe",
    "samples/ran/VirusShare_f267f725d69921556f969b3f9425dbb4.exe"

    # ... add the rest of your list here
]

def load_models():
    return {
        "rf_b": joblib.load("rf_behavior_model.joblib"),
        "rf_a": joblib.load("rf_artifact_model.joblib"),
        "xgb_b": joblib.load("xgb_behavior_model.joblib"),
        "xgb_a": joblib.load("xgb_artifact_model.joblib")
    }

def analyze_features(file_list):
    models = load_models()
    analysis_results = []

    print(f"🔍 Analyzing {len(file_list)} misclassified files...")

    for path in file_list:
        if not os.path.exists(path):
            continue
            
        try:
            # 1. Extract raw vector
            feats = extract_features_from_binary(path)
            raw_vec = np.array(vectorize_features(feats))
            
            # 2. Get base model probabilities
            p_rf_b = models["rf_b"].predict_proba(raw_vec[MODEL1_INDICES].reshape(1, -1))[0][1]
            p_rf_a = models["rf_a"].predict_proba(raw_vec[MODEL2_INDICES].reshape(1, -1))[0][1]
            p_xgb_b = models["xgb_b"].predict_proba(raw_vec[MODEL1_INDICES].reshape(1, -1))[0][1]
            p_xgb_a = models["xgb_a"].predict_proba(raw_vec[MODEL2_INDICES].reshape(1, -1))[0][1]
            
            # 3. Calculate Meta-stats
            avg_beh = (p_rf_b + p_xgb_b) / 2
            avg_art = (p_rf_a + p_xgb_a) / 2
            disag = abs(avg_beh - avg_art)
            
            probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])
            entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

            # 4. Extract Silver Bullets
            silver = raw_vec[SILVER_INDICES]

            # 5. Compile full 12-feature record for inspection
            analysis_results.append({
                "filename": os.path.basename(path),
                "p_rf_b": p_rf_b, "p_rf_a": p_rf_a,
                "p_xgb_b": p_xgb_b, "p_xgb_a": p_xgb_a,
                "avg_beh": avg_beh, "avg_art": avg_art,
                "disagreement": disag, "prob_entropy": entropy,
                "SILVER_valid_sig": silver[0],
                "SILVER_shadow_del": silver[1],
                "SILVER_size_anomaly": silver[2],
                "SILVER_file_entropy": silver[3]
            })
        except Exception as e:
            print(f"Error on {path}: {e}")

    return pd.DataFrame(analysis_results)

if __name__ == "__main__":
    df = analyze_features(MISCLASSIFIED_FILES)
    output_file = "scan_reports/misclassification_analysis.csv"
    df.to_csv(output_file, index=False)
    print(f"\n✅ Analysis complete. Check {output_file} to see which features were low.")
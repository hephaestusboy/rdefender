import joblib

MODEL_PATH = "fusion_model_v4.joblib"

# The exact 19 features constructed in 'build_fusion_features' and 'train_fold'
FUSION_FEATURE_NAMES = [
    "RF_Behavior_Prob",                 # 1
    "RF_Artifact_Prob",                 # 2
    "XGB_Behavior_Prob",                # 3
    "XGB_Artifact_Prob",                # 4
    "Avg_Behavior",                     # 5
    "Avg_Artifact",                     # 6
    "Model_Disagreement",               # 7
    "Probability_Entropy",              # 8
    "High_Artifact_Stealth_Flag",       # 9
    "High_Behavior_Stealth_Flag",       # 10
    "Joint_Confidence",                 # 11
    "RF_Diff (Artifact - Behavior)",    # 12
    "XGB_Diff (Artifact - Behavior)",   # 13
    "Max_Signal",                       # 14
    "Min_Signal",                       # 15
    "IS_SIGNATURE_VALID",               # 16
    "SHADOW_COPY_DELETION_STRINGS",     # 17
    "VIRTUAL_RAW_SIZE_ANOMALY",         # 18
    "FILE_ENTROPY"                      # 19
]

def load_meta_learner(path):
    # Load the pipeline
    pipeline = joblib.load(path)
    
    # Extract the actual XGBoost model from the pipeline
    meta_learner = pipeline.named_steps['meta_learner']
    
    if not hasattr(meta_learner, "feature_importances_"):
        raise ValueError("Model does not support feature importance")
    
    return meta_learner

def analyze_feature_importance(model):
    importances = model.feature_importances_
    
    # Zip the scores with our custom 19-feature list
    pairs = list(zip(FUSION_FEATURE_NAMES, importances))
    pairs.sort(key=lambda x: x[1], reverse=True)

    return pairs

if __name__ == "__main__":
    try:
        meta_learner = load_meta_learner(MODEL_PATH)
        ranked = analyze_feature_importance(meta_learner)

        print("\n========= FUSION META-LEARNER IMPORTANCE =========\n")
        for i, (name, score) in enumerate(ranked, 1):
            # Print as percentage for easier reading
            print(f"{i:02d}. {name:<35} {score * 100:>6.2f}%")
        print("\n==================================================\n")
        
    except Exception as e:
        print(f"❌ Error: {e}")

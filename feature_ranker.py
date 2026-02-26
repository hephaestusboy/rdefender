import joblib
import pandas as pd
import matplotlib.pyplot as plt

def analyze_importance():
    # Load the Fusion Pipeline
    fusion_pipe = joblib.load("fusion_model.joblib")
    
    # Access the XGBoost model inside the pipeline
    model = fusion_pipe.named_steps['meta_learner']
    
    # The 28 features we defined in train.py
    feature_names = [
        "p_rf_b", "p_rf_a", "p_xgb_b", "p_xgb_a", "avg_behavior", "avg_artifact",
        "conf_behavior", "conf_artifact", "behavior_score", "artifact_score",
        "disagreement", "avg_entropy", "artifact_dominance", "hi_art_lo_beh",
        "behavior_disag", "hi_beh_disag", "max_behavior", "max_artifact",
        "min_behavior", "min_artifact", "voted_behavior", "voted_artifact",
        "beh_unan_hi", "beh_any_hi", "art_hi_beh_lo", "cross_var",
        "behavior_dominance", "joint_confidence"
    ]

    importances = model.feature_importances_
    feat_imp = pd.Series(importances, index=feature_names).sort_values(ascending=False)

    print("\n🏆 Top 10 Decision Drivers:")
    print(feat_imp.head(10))
    
    return feat_imp

if __name__ == "__main__":
    analyze_importance()
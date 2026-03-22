import joblib
import numpy as np

# Import your custom schema and indices
from feature_schema import FEATURE_SCHEMA
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES

# The exact 21 features constructed in 'build_fusion_features' of evaluate8model.py
FUSION_8MODEL_FEATURES = [
    "RF_Behavior_Prob",                 # 1
    "RF_Artifact_Prob",                 # 2
    "XGB_Behavior_Prob",                # 3
    "XGB_Artifact_Prob",                # 4
    "LGBM_Behavior_Prob",               # 5
    "LGBM_Artifact_Prob",               # 6
    "CAT_Behavior_Prob",                # 7
    "CAT_Artifact_Prob",                # 8
    "Avg_Behavior",                     # 9
    "Avg_Artifact",                     # 10
    "Model_Disagreement",               # 11
    "Probability_Entropy",              # 12
    "High_Artifact_Stealth_Flag",       # 13
    "High_Behavior_Stealth_Flag",       # 14
    "Joint_Confidence",                 # 15
    "Max_Signal",                       # 16
    "Min_Signal",                       # 17
    "IS_SIGNATURE_VALID",               # 18
    "SHADOW_COPY_DELETION_STRINGS",     # 19
    "VIRTUAL_RAW_SIZE_ANOMALY",         # 20
    "FILE_ENTROPY"                      # 21
]

def get_importances(model):
    """Extracts feature importances safely, handling Pipelines and Calibrated models."""
    # If it's a Pipeline, extract the final step (the actual meta-learner/estimator)
    if hasattr(model, 'named_steps'):
        model = model.named_steps.get('meta_learner', list(model.named_steps.values())[-1])

    # Check if the model is wrapped in a calibrator (CalibratedClassifierCV)
    if hasattr(model, 'calibrated_classifiers_'):
        importances = []
        for clf in model.calibrated_classifiers_:
            # Handle different versions of scikit-learn
            base_model = getattr(clf, 'estimator', getattr(clf, 'base_estimator', None))
            if base_model:
                if hasattr(base_model, 'feature_importances_'):
                    importances.append(base_model.feature_importances_)
                elif hasattr(base_model, 'coef_'):
                    importances.append(np.abs(base_model.coef_[0]))
        
        if importances:
            return np.mean(importances, axis=0)
    
    # Fallback if the model is NOT calibrated
    if hasattr(model, 'feature_importances_'):
        return model.feature_importances_
    elif hasattr(model, 'coef_'):
        return np.abs(model.coef_[0])
        
    raise ValueError(f"Could not extract feature importances from {type(model)}")

def print_top_features(name, importances, feature_names, top_n=15):
    if importances is None:
        print(f"❌ Could not get importances for {name}")
        return
        
    print(f"\n{'='*65}")
    print(f" 🏆 {name.upper()} - TOP {top_n} FEATURES")
    print(f"{'='*65}")
    
    # Normalize to percentages if using arbitrary scores like linear coefficients
    if np.sum(importances) > 0:
        importances = importances / np.sum(importances)
        
    indices = np.argsort(importances)[::-1]
    for i in range(min(top_n, len(indices))):
        idx = indices[i]
        if idx < len(feature_names):
            print(f" {i+1:2d}. {importances[idx]*100:6.2f}% | {feature_names[idx]}")
        else:
            print(f" {i+1:2d}. {importances[idx]*100:6.2f}% | Feature_Index_{idx}")

def main():
    print("Loading 8-Model Ensemble Components...")
    try:
        models = {
            "RF Behavior": joblib.load("rf_behavior_model.joblib"),
            "RF Artifact": joblib.load("rf_artifact_model.joblib"),
            "XGB Behavior": joblib.load("xgb_behavior_model.joblib"),
            "XGB Artifact": joblib.load("xgb_artifact_model.joblib"),
            "LGBM Behavior": joblib.load("lgbm_behavior_model.joblib"),
            "LGBM Artifact": joblib.load("lgbm_artifact_model.joblib"),
            "CAT Behavior": joblib.load("catboost_behavior_model.joblib"),
            "CAT Artifact": joblib.load("catboost_artifact_model.joblib"),
            "Fusion Meta-Learner": joblib.load("fusion_8model.joblib")
        }
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        return

    # Map the indices to the actual string names
    behavior_names = [FEATURE_SCHEMA[i] for i in MODEL1_INDICES]
    artifact_names = [FEATURE_SCHEMA[i] for i in MODEL2_INDICES]

    # 1. Base Models
    for name, model in models.items():
        if "Fusion" in name: 
            feat_names = FUSION_8MODEL_FEATURES
        else:
            feat_names = behavior_names if "Behavior" in name else artifact_names
        
        try:
            imps = get_importances(model)
            print_top_features(name, imps, feat_names, top_n=21 if "Fusion" in name else 15)
        except Exception as e:
            print(f"\n⚠️ Could not analyze {name}: {e}")

if __name__ == "__main__":
    main()
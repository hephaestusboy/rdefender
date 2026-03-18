import joblib
import numpy as np

# Import your custom schema and indices
from feature_schema import FEATURE_SCHEMA
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES

def get_calibrated_importances(model):
    """Digs inside a CalibratedClassifierCV wrapper to average the base estimator importances."""
    # Check if the model is wrapped in a calibrator
    if hasattr(model, 'calibrated_classifiers_'):
        importances = []
        for clf in model.calibrated_classifiers_:
            # Handle different versions of scikit-learn (estimator vs base_estimator)
            base_model = getattr(clf, 'estimator', getattr(clf, 'base_estimator', None))
            if base_model and hasattr(base_model, 'feature_importances_'):
                importances.append(base_model.feature_importances_)
        
        if importances:
            # Average the importances across all cross-validation folds
            return np.mean(importances, axis=0)
        else:
            raise ValueError("Base estimators inside calibrator do not have feature_importances_.")
    
    # Fallback if the model is NOT calibrated
    elif hasattr(model, 'feature_importances_'):
        return model.feature_importances_
    else:
        raise AttributeError(f"Model {type(model)} does not support feature importances.")

def print_feature_importance(model_name, model, feature_names, top_n=30):
    """Extracts and prints the top N most important features."""
    print(f"\n{'='*60}")
    print(f" 🔍 {model_name.upper()} - TOP {top_n} FEATURES")
    print(f"{'='*60}")
    
    # Get importances (safely handling calibration wrappers)
    importances = get_calibrated_importances(model)
    
    # Sort indices in descending order of importance
    indices = np.argsort(importances)[::-1]
    
    # Print the top N
    for i in range(min(top_n, len(indices))):
        idx = indices[i]
        feature_name = feature_names[idx]
        score = importances[idx]
        print(f" {i+1:2d}. {score*100:5.2f}% | {feature_name}")

def main():
    print("Loading Base Models...")
    try:
        models = {
            "Random Forest (Behavior)": joblib.load("rf_behavior_model.joblib"),
            "Random Forest (Artifact)": joblib.load("rf_artifact_model.joblib"),
            "XGBoost (Behavior)": joblib.load("xgb_behavior_model.joblib"),
            "XGBoost (Artifact)": joblib.load("xgb_artifact_model.joblib"),
        }
    except FileNotFoundError as e:
        print(f"❌ Error loading models: {e}")
        return

    # Map the indices to the actual string names from your schema
    behavior_features = [FEATURE_SCHEMA[i] for i in MODEL1_INDICES]
    artifact_features = [FEATURE_SCHEMA[i] for i in MODEL2_INDICES]

    # Display Importances
    print_feature_importance("Random Forest (Behavior)", models["Random Forest (Behavior)"], behavior_features)
    print_feature_importance("XGBoost (Behavior)", models["XGBoost (Behavior)"], behavior_features)
    
    print_feature_importance("Random Forest (Artifact)", models["Random Forest (Artifact)"], artifact_features)
    print_feature_importance("XGBoost (Artifact)", models["XGBoost (Artifact)"], artifact_features)
    
    print(f"\n{'='*60}")

if __name__ == "__main__":
    main()

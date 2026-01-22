import joblib
import numpy as np

from feature_schema import FEATURE_SCHEMA


MODEL_PATH = "xgb_model.joblib"
TOP_K = 25   # show top N features


def load_model(path):
    model = joblib.load(path)
    if not hasattr(model, "feature_importances_"):
        raise ValueError("Model does not support feature importance")
    return model


def analyze_feature_importance(model):
    importances = model.feature_importances_
    feature_names = FEATURE_SCHEMA

    pairs = list(zip(feature_names, importances))
    pairs.sort(key=lambda x: x[1], reverse=True)

    return pairs


if __name__ == "__main__":
    model = load_model(MODEL_PATH)
    ranked = analyze_feature_importance(model)

    print("\n========= TOP FEATURE IMPORTANCE =========\n")
    for i, (name, score) in enumerate(ranked[:TOP_K], 1):
        print(f"{i:02d}. {name:<35} {score:.6f}")

    print("\n==========================================\n")

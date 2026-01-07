from feature_schema import FEATURE_SCHEMA

def vectorize_features(feature_dict):
    """
    Converts feature dictionary → fixed 86-length vector
    Missing features are filled with 0
    """
    vector = [feature_dict.get(f, 0) for f in FEATURE_SCHEMA]

    assert len(vector) == 86, f"Feature vector size mismatch: {len(vector)}"

    return vector

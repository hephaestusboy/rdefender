from feature_schema import FEATURE_SCHEMA

def vectorize_features(feature_dict):
    """
    Converts feature dictionary → fixed 86-length vector
    Missing features are filled with 0
    """
    vector = [feature_dict.get(f, 0) for f in FEATURE_SCHEMA]

    assert len(vector) == len(FEATURE_SCHEMA), \
    f"Feature vector size mismatch: {len(vector)} vs {len(FEATURE_SCHEMA)}"

    return vector

def debug_vector(vector):
    for name, value in zip(FEATURE_SCHEMA, vector):
        print(f"{name}: {value}")


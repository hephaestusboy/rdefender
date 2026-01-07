from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from feature_schema import FEATURE_SCHEMA

# Indices of critical features in schema
CRITICAL_FEATURES = {
    "API_CRYPTO_CONTEXT",
    "API_CRYPTO_HASH",
    "API_CRYPTO_ENCRYPT",
    "API_FILE_READ",
    "API_FILE_WRITE",
    "API_FILE_DELETE",
    "API_FILE_RENAME",
    "API_DIRECTORY_ENUM",
    "API_DEBUG_DETECTION",
    "API_DELAY_EXECUTION",
    "API_SOCKET_CONNECT",
    "API_HTTP_REQUEST",
    "DROP_ENCRYPTED_EXTENSIONS",
    "DROP_RANDOM_NAMED_FILES",
    "REG_KEY_CREATE",
    "REG_VALUE_SET",
    "REG_SERVICE_CREATE_DELETE",
}

def predict_ransomware(features):
    vector = vectorize_features(features)

    # sanity check
    assert len(vector) == 86

    critical_score = sum(
        features.get(f, 0) for f in CRITICAL_FEATURES
    )

    secondary_score = sum(vector) - critical_score

    score = (2 * critical_score) + secondary_score

    if score >= 18:
        label = 1
        confidence = min(0.99, 0.7 + score / 40)
    elif score >= 12:
        label = 1
        confidence = min(0.95, 0.6 + score / 40)
    else:
        label = 0
        confidence = max(0.05, 0.5 - score / 40)

    return label, round(confidence, 2), score


def analyze_file(filepath):
    features = extract_features_from_binary(filepath)

    vector = vectorize_features(features)
    print(f"✔ Extracted feature count: {len(vector)} (EXPECTED: 86)")

    label, confidence, score = predict_ransomware(features)

    verdict = "RANSOMWARE" if label == 1 else "BENIGN"

    print("\n===== RANSOMWARE ANALYSIS =====")
    print(f"File       : {filepath}")
    print(f"Verdict    : {verdict}")
    print(f"Confidence : {confidence}")
    print(f"Risk Score : {score}")
    print("================================\n")

    return label, confidence, score


if __name__ == "__main__":
    analyze_file("1mb.exe")

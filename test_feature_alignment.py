from static_feature_extractor import extract_features_from_binary
from feature_schema import FEATURE_SCHEMA

def validate_extractor_output(feature_dict):
    for k in feature_dict:
        if k not in FEATURE_SCHEMA:
            print("⚠️ Extractor produced unknown feature:", k)

if __name__ == "__main__":
    sample_path = "samples/ransomware/26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739.bin"

    features = extract_features_from_binary(sample_path)
    validate_extractor_output(features)

    print("Total features produced:", len(features))
    print("Total features in schema:", len(FEATURE_SCHEMA))

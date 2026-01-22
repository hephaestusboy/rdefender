import numpy as np
from imblearn.over_sampling import SMOTE


def apply_smote(X, y, random_state=42):
    """
    Apply SMOTE on feature vectors.
    Only oversamples the minority class (ransomware).
    """

    smote = SMOTE(
        sampling_strategy="auto",
        k_neighbors=5,
        random_state=random_state
    )

    X_resampled, y_resampled = smote.fit_resample(X, y)

    print("SMOTE applied:")
    print(f"Original samples : {len(X)}")
    print(f"After SMOTE      : {len(X_resampled)}")

    return X_resampled, y_resampled

def apply_mixup(X, y, alpha=0.2, num_samples=None, seed=42):
    """
    MixUp applied ONLY to ransomware samples (y == 1).
    Prevents label noise from benign ↔ ransomware mixing.
    """

    rng = np.random.default_rng(seed)

    ransom_idx = np.where(y == 1)[0]

    if len(ransom_idx) < 2:
        print("Not enough ransomware samples for MixUp")
        return X, y

    if num_samples is None:
        num_samples = len(ransom_idx)

    X_new = []
    y_new = []

    for _ in range(num_samples):
        i, j = rng.choice(ransom_idx, size=2, replace=False)
        lam = rng.beta(alpha, alpha)

        x_mix = lam * X[i] + (1 - lam) * X[j]

        X_new.append(x_mix)
        y_new.append(1)  # always ransomware

    X_aug = np.vstack([X, np.array(X_new)])
    y_aug = np.concatenate([y, np.array(y_new)])

    print("MixUp (ransomware-only) applied:")
    print(f"Original samples : {len(X)}")
    print(f"After MixUp     : {len(X_aug)}")

    return X_aug, y_aug

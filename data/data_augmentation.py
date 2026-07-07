import numpy as np
from sklearn.utils import resample

def augment_data(X, y, sample_size=1000):
    # Simple data augmentation example
    X_resampled, y_resampled = resample(X, y, n_samples=sample_size, random_state=42)
    return X_resampled, y_resampled
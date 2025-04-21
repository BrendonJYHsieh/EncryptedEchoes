#!/usr/bin/env python3
"""
Encrypted Echoes

This script implements OS identification from TLS fingerprints based on the paper:
"Using TLS Fingerprints for OS Identification in Encrypted Traffic"
(https://ieeexplore.ieee.org/document/9110319)

Each feature is treated as a binary one-hot encoded vector where order is preserved,
representing absence or presence of encryption types or suites.

Dataset required: "flows_anonymized" directory containing CSV files
Dataset available at: https://zenodo.org/records/3461771
"""

import joblib
import glob
import pandas as pd
import numpy as np
import xgboost as xgb
import os

from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_recall_fscore_support,
    confusion_matrix,
)

def parse_hex_list(raw_str):
    """Parse hex string into list of 4-character hex chunks"""
    if pd.isna(raw_str):
        return []

    # keep hex chars only, split every 4-hex
    clean = "".join(x for x in raw_str if x in "0123456789abcdefABCDEF")
    return [clean[i : i + 4].lower() for i in range(0, len(clean), 4)]

def to_slots(series, k, prefix):
    """Convert series of lists to fixed-length columns with missing values padded"""
    return pd.DataFrame(
        series.apply(lambda lst: (lst + ["MISSING"] * k)[:k]).to_list(),
        columns=[f"{prefix}_pos{i}" for i in range(k)],
    )

def preprocess_data(files=None, save=True):
    """Preprocess the data and optionally save the results
    
    Args:
        files: List of files to process, defaults to first 15 ground truth files
        save: Whether to save the preprocessed data to disk
        
    Returns:
        tuple: (X_encoded, y_int, os_labels, pre) - encoded features, encoded labels, 
               label names, and the encoder
    """
    print("Starting: Reading and combining CSV files...")
    # Read and combine CSV files
    if files is None:
        files = sorted(glob.glob("flows_anonymized/*_ground_truth_tls_only.csv"))[:1]

    KEEP_COLS = [
        "TLS Client Version",
        "Client Cipher Suites",
        "TLS Extension Types",
        "TLS Extension Lengths",
        "TLS Elliptic Curves",
        "Ground Truth OS",
    ]
    
    df_list = []
    for path in files:
        df_part = pd.read_csv(path, usecols=KEEP_COLS, low_memory=False)
        df_list.append(df_part)

    tls_df = pd.concat(df_list, ignore_index=True)
    print("Combined shape:", tls_df.shape)
    print(tls_df.columns)

    print("Cleaning data...")
    # Clean data
    tls_df = tls_df.dropna().reset_index(drop=True)

    print("Parsing hex fields into lists...")
    # Parse hex fields into lists
    tls_df["cipher_list"] = tls_df["Client Cipher Suites"].apply(parse_hex_list)
    tls_df["group_list"] = tls_df["TLS Elliptic Curves"].apply(parse_hex_list)
    tls_df["ext_id_list"] = tls_df["TLS Extension Types"].apply(parse_hex_list)
    tls_df["ext_len_list"] = tls_df["TLS Extension Lengths"].apply(parse_hex_list)

    # Define constants for feature extraction
    K_CIPHER = 8    # first 8 cipher IDs
    K_GROUP = 8     # first 8 supported-group IDs
    K_EXT = 100     # first 100 extension IDs
    K_EXLEN = 100   # first 100 extension lengths

    print("Preparing features...")
    # Prepare features
    X_raw = pd.concat(
        [
            to_slots(tls_df["cipher_list"], K_CIPHER, "cipher"),
            to_slots(tls_df["group_list"], K_GROUP, "group"),
            to_slots(tls_df["ext_id_list"], K_EXT, "extid"),
            to_slots(tls_df["ext_len_list"], K_EXLEN, "extlen"),
            tls_df[["TLS Client Version"]],
        ],
        axis=1,
    )

    y = tls_df["Ground Truth OS"]

    print("Performing one-hot encoding...")
    # One-hot encoding
    onehot = OneHotEncoder(handle_unknown="ignore")
    pre = ColumnTransformer([("oh", onehot, X_raw.columns)], sparse_threshold=0.3)

    X_encoded = pre.fit_transform(X_raw)  # sparse CSR matrix
    
    # Convert to encodings for labels
    y_int, os_labels = pd.factorize(y)  # os_labels keeps the names
    
    if save:
        # Create directory if it doesn't exist
        os.makedirs("preprocessed", exist_ok=True)
        
        # Save preprocessed data
        joblib.dump(X_encoded, "preprocessed/X_encoded.joblib")
        joblib.dump(y_int, "preprocessed/y_int.joblib")
        joblib.dump(os_labels, "preprocessed/os_labels.joblib")
        joblib.dump(pre, "preprocessed/tls_onehot_encoder.joblib")
        print("Preprocessed data saved to 'preprocessed/' directory")
    
    return X_encoded, y_int, os_labels, pre

def main(use_preprocessed=True):
    """Main function to train and evaluate the model
    
    Args:
        use_preprocessed: Whether to use preprocessed data if available
    """
    preprocessed_path = "preprocessed"
    
    # Check if preprocessed data exists and should be used
    if use_preprocessed and os.path.exists(preprocessed_path):
        try:
            print("Loading preprocessed data...")
            X_encoded = joblib.load(f"{preprocessed_path}/X_encoded.joblib")
            y_int = joblib.load(f"{preprocessed_path}/y_int.joblib")
            os_labels = joblib.load(f"{preprocessed_path}/os_labels.joblib")
            pre = joblib.load(f"{preprocessed_path}/tls_onehot_encoder.joblib")
            print("Preprocessed data loaded successfully")
        except Exception as e:
            print(f"Error loading preprocessed data: {e}")
            print("Falling back to preprocessing from raw data...")
            X_encoded, y_int, os_labels, pre = preprocess_data()
    else:
        print("Preprocessing data from scratch...")
        X_encoded, y_int, os_labels, pre = preprocess_data()

    print("Preparing data for model training...")
    # Prepare for model training
    X_train, X_test, y_train, y_test = train_test_split(
        X_encoded, y_int, test_size=0.30, random_state=42, stratify=y_int
    )

    print("Training XGBoost model...")
    # Train XGBoost model
    xgb_clf = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=len(os_labels),
        tree_method="exact",
        max_depth=8,
        n_estimators=400,
        learning_rate=0.05,
    )

    xgb_clf.fit(X_train, y_train)
    print("Model training complete, generating predictions...")
    y_pred = xgb_clf.predict(X_test)

    print("Evaluating model performance...")
    # Evaluate model
    print("XGBoost accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred, target_names=os_labels))

    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion matrix\n", cm)

    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")
    print(f"Macro-avg  precision={prec:.4f}  recall={rec:.4f}  f1={f1:.4f}")
    
    # Save model for future use
    joblib.dump(xgb_clf, "tls_os_classifier.joblib")
    print("Model saved to tls_os_classifier.joblib")
    print("Process complete!")

if __name__ == "__main__":
    main()
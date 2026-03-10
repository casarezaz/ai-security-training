#!/usr/bin/env python3
"""
Session 2: Feature Engineering & First Models
Project 1: Network Intrusion Detection with Deep Learning
AI x Cybersecurity Convergence Training

Run with: python notebooks/session2_first_models.py
Make sure your conda env is active: conda activate aiml-cyber
"""
import pandas as pd
import numpy as np
import os
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, average_precision_score
)
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# STEP 1: LOAD AND CLEAN ALL DATA
# ============================================================================
print("=" * 60)
print("  Session 2: Feature Engineering & First Models")
print("  Network Intrusion Detection (CICIDS2017)")
print("=" * 60)

data_path = os.path.expanduser("~/aiml-cybersecurity/data/raw/MachineLearningCVE/")
output_path = os.path.expanduser("~/aiml-cybersecurity/data/processed/")
report_path = os.path.expanduser("~/aiml-cybersecurity/reports/")
os.makedirs(output_path, exist_ok=True)
os.makedirs(report_path, exist_ok=True)

# Check if cleaned data already exists
clean_file = os.path.join(output_path, "cicids2017_clean.csv")
if os.path.exists(clean_file):
    print("\n[*] Loading pre-cleaned data...")
    df = pd.read_csv(clean_file, low_memory=False)
else:
    print("\n[*] Loading all CSV files...")
    files = sorted(os.listdir(data_path))
    dfs = []
    for f in files:
        if not f.endswith('.csv'):
            continue
        filepath = os.path.join(data_path, f)
        chunk = pd.read_csv(filepath, low_memory=False)
        chunk.columns = chunk.columns.str.strip()
        print(f"    {f}: {len(chunk):,} rows")
        dfs.append(chunk)

    df = pd.concat(dfs, ignore_index=True)
    print(f"\n    Total: {len(df):,} rows, {df.shape[1]} columns")

    # Clean
    print("\n[*] Cleaning data...")
    for col in ['Flow Bytes/s', 'Flow Packets/s']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    rows_before = len(df)
    df.dropna(inplace=True)
    print(f"    Dropped {rows_before - len(df)} rows with NaN/inf")

    # Remove duplicate column
    if 'Fwd Header Length.1' in df.columns:
        df.drop('Fwd Header Length.1', axis=1, inplace=True)

    # Save cleaned version
    df.to_csv(clean_file, index=False)
    print(f"    Saved cleaned data: {clean_file}")

print(f"\n    Working with {len(df):,} rows, {df.shape[1]} columns")

# ============================================================================
# STEP 2: LABEL ENCODING
# ============================================================================
print("\n" + "=" * 60)
print("  Step 2: Preparing Labels")
print("=" * 60)

# Binary label
df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)

# Multiclass label encoding
le = LabelEncoder()
df['label_encoded'] = le.fit_transform(df['Label'])

print(f"\n  Label Distribution:")
for label, count in df['Label'].value_counts().items():
    pct = count / len(df) * 100
    indicator = "  *** RARE" if count < 100 else ""
    print(f"    {label:40s} {count:>10,}  ({pct:5.2f}%){indicator}")

print(f"\n  Binary split: {df['is_attack'].sum():,} attacks / {(df['is_attack']==0).sum():,} benign")

# ============================================================================
# STEP 3: FEATURE PREPARATION
# ============================================================================
print("\n" + "=" * 60)
print("  Step 3: Feature Preparation")
print("=" * 60)

feature_cols = [c for c in df.columns if c not in ['Label', 'is_attack', 'label_encoded']]
X = df[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
y_binary = df['is_attack']
y_multi = df['label_encoded']

print(f"\n  Features: {len(feature_cols)}")
print(f"  Sample features: {feature_cols[:10]}...")

# ============================================================================
# STEP 4: TRAIN/TEST SPLIT
# ============================================================================
print("\n" + "=" * 60)
print("  Step 4: Stratified Train/Test Split (80/20)")
print("=" * 60)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
)

# Also split multiclass for later
_, _, y_train_multi, y_test_multi = train_test_split(
    X, y_multi, test_size=0.2, random_state=42, stratify=y_binary
)

print(f"\n  Train set: {len(X_train):,} samples")
print(f"    Attacks: {y_train.sum():,} ({y_train.mean()*100:.1f}%)")
print(f"    Benign:  {(y_train==0).sum():,} ({(1-y_train.mean())*100:.1f}%)")
print(f"\n  Test set:  {len(X_test):,} samples")
print(f"    Attacks: {y_test.sum():,} ({y_test.mean()*100:.1f}%)")
print(f"    Benign:  {(y_test==0).sum():,} ({(1-y_test.mean())*100:.1f}%)")

# ============================================================================
# STEP 5: RANDOM FOREST — BINARY CLASSIFICATION
# ============================================================================
print("\n" + "=" * 60)
print("  Step 5: Random Forest (Binary: Attack vs Benign)")
print("=" * 60)

print("\n  Training Random Forest (100 trees, balanced weights)...")
start = time.time()

rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_leaf=5,
    class_weight='balanced',  # Handles class imbalance
    random_state=42,
    n_jobs=-1  # Use all CPU cores
)
rf.fit(X_train, y_train)
rf_time = time.time() - start
print(f"  Training time: {rf_time:.1f} seconds")

# Predictions
y_pred_rf = rf.predict(X_test)
y_prob_rf = rf.predict_proba(X_test)[:, 1]

# Classification report
print("\n  --- Binary Classification Report (Random Forest) ---\n")
report = classification_report(y_test, y_pred_rf, target_names=['Benign', 'Attack'])
print(report)

# ROC-AUC
auc_rf = roc_auc_score(y_test, y_prob_rf)
print(f"  ROC-AUC Score: {auc_rf:.4f}")

# Confusion matrix with security interpretation
tn, fp, fn, tp = confusion_matrix(y_test, y_pred_rf).ravel()
print(f"\n  === Security Metrics ===")
print(f"  True Negatives:  {tn:>10,}  (benign correctly identified)")
print(f"  False Positives: {fp:>10,}  (benign flagged as attack — analyst wastes time)")
print(f"  False Negatives: {fn:>10,}  (ATTACKS MISSED — the dangerous ones)")
print(f"  True Positives:  {tp:>10,}  (attacks correctly caught)")
print(f"\n  Detection Rate (Recall): {tp/(tp+fn)*100:.2f}%")
print(f"  False Alarm Rate:        {fp/(fp+tn)*100:.2f}%")
print(f"  Precision:               {tp/(tp+fp)*100:.2f}%")

# ============================================================================
# STEP 6: FEATURE IMPORTANCE
# ============================================================================
print("\n" + "=" * 60)
print("  Step 6: Feature Importance (What the Model Learned)")
print("=" * 60)

importances = pd.Series(rf.feature_importances_, index=feature_cols).sort_values(ascending=False)

print("\n  Top 20 Most Important Features:\n")
for i, (feat, imp) in enumerate(importances.head(20).items()):
    bar = '█' * int(imp * 100)
    print(f"  {i+1:3d}. {feat:35s} {imp:.4f}  {bar}")

# Security interpretation
print("\n  === Security Interpretation ===")
print("  The model's top features reveal what distinguishes attacks from normal traffic.")
print("  Features related to packet sizes, flow timing, and TCP flags are typically")
print("  the strongest discriminators — this aligns with known network attack signatures.")

# Save feature importances
importances.to_csv(os.path.join(report_path, "feature_importances_rf.csv"))

# ============================================================================
# STEP 7: MULTICLASS CLASSIFICATION
# ============================================================================
print("\n" + "=" * 60)
print("  Step 7: Random Forest (Multiclass: Attack Type Classification)")
print("=" * 60)

print("\n  Training multiclass model...")
start = time.time()

rf_multi = RandomForestClassifier(
    n_estimators=100,
    max_depth=25,
    min_samples_leaf=3,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
rf_multi.fit(X_train, y_train_multi)
rf_multi_time = time.time() - start
print(f"  Training time: {rf_multi_time:.1f} seconds")

y_pred_multi = rf_multi.predict(X_test)

print("\n  --- Multiclass Classification Report ---\n")
multi_report = classification_report(
    y_test_multi, y_pred_multi,
    target_names=le.classes_,
    zero_division=0
)
print(multi_report)

# ============================================================================
# STEP 8: VISUALIZATIONS
# ============================================================================
print("\n" + "=" * 60)
print("  Step 8: Generating Visualizations")
print("=" * 60)

fig_path = os.path.join(report_path, "figures")
os.makedirs(fig_path, exist_ok=True)

# 8a. Feature importance bar chart
plt.figure(figsize=(12, 8))
importances.head(20).plot(kind='barh', color='steelblue')
plt.xlabel('Importance Score')
plt.title('Top 20 Features — Random Forest (Binary Classification)')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig(os.path.join(fig_path, 'feature_importances.png'), dpi=150)
plt.close()
print("  [✓] Saved feature_importances.png")

# 8b. Confusion matrix heatmap (binary)
plt.figure(figsize=(8, 6))
cm = confusion_matrix(y_test, y_pred_rf)
sns.heatmap(cm, annot=True, fmt=',d', cmap='Blues',
            xticklabels=['Benign', 'Attack'],
            yticklabels=['Benign', 'Attack'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix — Binary Classification')
plt.tight_layout()
plt.savefig(os.path.join(fig_path, 'confusion_matrix_binary.png'), dpi=150)
plt.close()
print("  [✓] Saved confusion_matrix_binary.png")

# 8c. Confusion matrix heatmap (multiclass)
plt.figure(figsize=(16, 14))
cm_multi = confusion_matrix(y_test_multi, y_pred_multi)
sns.heatmap(cm_multi, annot=True, fmt=',d', cmap='Blues',
            xticklabels=le.classes_, yticklabels=le.classes_)
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix — Multiclass (Attack Type)')
plt.xticks(rotation=45, ha='right')
plt.yticks(rotation=0)
plt.tight_layout()
plt.savefig(os.path.join(fig_path, 'confusion_matrix_multiclass.png'), dpi=150)
plt.close()
print("  [✓] Saved confusion_matrix_multiclass.png")

# 8d. Precision-Recall curve
precision, recall, thresholds = precision_recall_curve(y_test, y_prob_rf)
avg_prec = average_precision_score(y_test, y_prob_rf)

plt.figure(figsize=(8, 6))
plt.plot(recall, precision, color='steelblue', lw=2, label=f'RF (AP={avg_prec:.3f})')
plt.xlabel('Recall (Detection Rate)')
plt.ylabel('Precision')
plt.title('Precision-Recall Curve — Attack Detection')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(fig_path, 'precision_recall_curve.png'), dpi=150)
plt.close()
print("  [✓] Saved precision_recall_curve.png")

# ============================================================================
# STEP 9: SAVE RESULTS SUMMARY
# ============================================================================
print("\n" + "=" * 60)
print("  Step 9: Results Summary")
print("=" * 60)

summary = f"""
Session 2 Results — Network Intrusion Detection
================================================
Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}
Dataset: CICIDS2017 ({len(df):,} samples)
Train/Test Split: 80/20 (stratified)

BINARY CLASSIFICATION (Attack vs Benign)
-----------------------------------------
Model: Random Forest (100 trees, balanced weights)
Training Time: {rf_time:.1f} seconds
ROC-AUC: {auc_rf:.4f}
Detection Rate: {tp/(tp+fn)*100:.2f}%
False Alarm Rate: {fp/(fp+tn)*100:.2f}%
Precision: {tp/(tp+fp)*100:.2f}%

Confusion Matrix:
  True Negatives:  {tn:>10,}
  False Positives: {fp:>10,}
  False Negatives: {fn:>10,}
  True Positives:  {tp:>10,}

Top 5 Features:
{importances.head(5).to_string()}

MULTICLASS CLASSIFICATION (Attack Type)
-----------------------------------------
{multi_report}
"""

summary_file = os.path.join(report_path, "session2_results.txt")
with open(summary_file, 'w') as f:
    f.write(summary)

print(summary)
print(f"\n  Full report saved to: {summary_file}")
print(f"  Feature importances: {report_path}/feature_importances_rf.csv")
print(f"  Figures: {fig_path}/")
print("\n" + "=" * 60)
print("  Session 2 Complete!")
print("  Next: Session 3 — XGBoost, deep learning, and adversarial testing")
print("=" * 60)

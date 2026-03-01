# Project 1 — Session 1: Environment Setup & Data Exploration
## Network Intrusion Detection with Deep Learning (CICIDS2017)

---

## What You're Building (Big Picture)

You're building a **Network Intrusion Detection System (NIDS)** — software that watches network traffic flowing through a network and flags suspicious activity. Think of it like a security camera, but for data packets instead of people.

**Traditional IDS works like a wanted poster:** It has a list of known attack patterns ("signatures") and checks traffic against them. Problem? It can't catch anything new.

**Your ML-based IDS will learn what "normal" traffic looks like and flag anything unusual** — including attacks it's never seen before (zero-day attacks). This is why AI transforms cybersecurity.

Here's the journey ahead:
1. **Session 1 (now)**: Explore the CICIDS2017 dataset
2. **Session 2**: Build ML models (Random Forest, XGBoost, Deep Learning)
3. **Session 3**: Evaluate with security-relevant metrics
4. **Session 4**: Deploy and explain predictions

Let's get started.

---

## Part 1: Understanding the Dataset Before You Touch Code

### What is CICIDS2017?

The **Canadian Institute for Cybersecurity Intrusion Detection Dataset (2017)** is one of the best-labeled network datasets available. Here's what researchers did to create it:

1. **Setup a realistic network** with servers, workstations, routers, and switches
2. **Ran normal user activity** for 5 days:
   - Web browsing
   - Email (SMTP, POP3, IMAP)
   - File transfers (FTP)
   - SSH access
   - DNS queries
3. **Simultaneously launched REAL attacks** against the network
4. **Captured ALL network traffic** and labeled each flow

The result: 2.8 million labeled network flows, with about 80% benign (normal) and 20% malicious (attacks).

### Attack Types in the Dataset

| Day | Attack Type | What It Does | Cybersecurity Context |
|-----|-------------|-------------|----------------------|
| All Days | Benign | Normal network activity (baseline) | No attack; legitimate user behavior |
| Tuesday | Brute Force (FTP/SSH) | Attacker tries thousands of username/password combinations | Common initial access technique (MITRE ATT&CK: T1110 - Brute Force) |
| Wednesday | DoS / DDoS | Flood server with requests to make it unavailable | Denial of Service; can take down critical infrastructure |
| Thursday AM | Web Attacks | SQL injection, XSS, file inclusion against web servers | Target web applications; can steal data or take control |
| Thursday PM | Infiltration | Attacker planted on network, exfiltrating data or pivoting | Post-compromise persistence; espionage scenario |
| Friday AM | Botnet (Mirai) | Infected IoT devices controlled to perform coordinated attacks | Malware; can recruit your network to attack others |
| Friday PM | Port Scan | Attacker maps network to find open services | Reconnaissance; first step in attack chain |

**Key insight for your model:** These attacks have different "fingerprints" in network traffic. Port scans look different from DDoS, which looks different from brute force. Your model will learn these patterns.

### What's in Each Row? The 84 Features Explained

Each row in the dataset represents one **network flow** — a bidirectional conversation between two IP addresses. It has 84 features divided into groups:

| Feature Group | Examples | Why It Matters for Security |
|---------------|----------|---------------------------|
| **Basic Flow Info** | Source IP, Destination IP, Source Port, Destination Port | Tells you who's talking to whom |
| **Packet Counts** | Total Fwd Packets, Total Bwd Packets | Asymmetric patterns reveal attacks (e.g., DDoS: many outbound) |
| **Byte Counts** | Total Fwd Bytes, Total Bwd Bytes | Data volume; botnet C2 uses small packets, data exfil uses large packets |
| **Timing** | Flow Duration, Inter-Arrival Time Mean/Min/Max | Attack timing patterns (e.g., brute force: fast attempts; infiltration: slow) |
| **TCP Flags** | Fwd PSH Flags, Fwd SYN Flags, Bwd RST Flags | Unusual flag combos indicate scans or protocol violations |
| **Packet Length** | Fwd Packet Length Mean/Std/Max/Min | Payload size; exploit payloads often large |
| **Statistical** | Flow Bytes/s, Flow Packets/s, Fwd Header Bytes | Bandwidth and efficiency; anomalies reveal attacks |

**Total of 84 features** including variations for forward direction (client→server) and backward (server→client).

---

## Part 2: Environment Setup

### Step 2.1: Create Project Directory Structure

Open your terminal and run these commands:

```bash
# Create the project directory
mkdir -p ~/aiml-cybersecurity/projects/project_01_nids
cd ~/aiml-cybersecurity/projects/project_01_nids

# Create subdirectories
mkdir -p data/raw data/processed notebooks models logs

# Create Python virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
```

After activation, your terminal should show `(venv)` at the start of the prompt.

### Step 2.2: Install Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install required packages
pip install \
    pandas==2.0.3 \
    numpy==1.24.3 \
    scikit-learn==1.3.0 \
    matplotlib==3.7.2 \
    seaborn==0.12.2 \
    jupyter==1.0.0 \
    scipy==1.11.2

# Verify installation
python -c "import pandas; import numpy; import sklearn; print('All packages installed successfully!')"
```

### Step 2.3: Download the CICIDS2017 Dataset

You have two options:

#### Option A: Direct Download from UNB (Recommended)
The dataset is about 3.6 GB and includes the complete network traffic in CSV format.

```bash
# Navigate to your data/raw directory
cd ~/aiml-cybersecurity/projects/project_01_nids/data/raw

# Download from UNB (this may take several minutes)
# The file is CICIDS2017.zip
wget https://www.unb.ca/cic/datasets/ids-2017.html
# Or manually download from the link above

# Unzip (about 12 GB uncompressed)
unzip CICIDS2017.zip
```

**Files you'll get:**
- `Monday-WorkingHours.pcap_ISCX.csv` (benign traffic)
- `Tuesday-WorkingHours.pcap_ISCX.csv` (brute force attacks)
- `Wednesday-WorkingHours.pcap_ISCX.csv` (DoS/DDoS attacks)
- `Thursday-WorkingHours-Morning.pcap_ISCX.csv` (web attacks)
- `Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv` (infiltration)
- `Friday-WorkingHours-Morning.pcap_ISCX.csv` (botnet)
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (port scan)

#### Option B: Kaggle Dataset (Alternative)
If UNB is slow, Kaggle hosts a processed version:

```bash
# Install Kaggle CLI
pip install kaggle

# Download dataset
kaggle datasets download -d cicdataset/cicids2017

# Unzip
unzip cicids2017.zip
```

### Step 2.4: Verify Directory Structure

After setup, your project should look like this:

```
~/aiml-cybersecurity/projects/project_01_nids/
├── venv/
├── data/
│   ├── raw/
│   │   ├── Monday-WorkingHours.pcap_ISCX.csv
│   │   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   │   ├── Wednesday-WorkingHours.pcap_ISCX.csv
│   │   ├── Thursday-WorkingHours-Morning.pcap_ISCX.csv
│   │   ├── Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv
│   │   ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│   │   └── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│   └── processed/
├── notebooks/
├── models/
├── logs/
└── venv/
```

---

## Part 3: Data Exploration Script

### Overview

In this section, you'll run a comprehensive exploratory data analysis (EDA) script that:
- Loads all 7 CSV files and combines them
- Cleans the data (handles missing values, infinite values)
- Analyzes the class distribution (important for ML!)
- Explores key security-relevant features
- Generates visualizations
- Saves cleaned data for modeling

### Step 3.1: Create the Exploration Script

Create a file called `session1_exploration.py` in your project root:

```python
"""
Project 1, Session 1: Data Exploration & Cleaning
Network Intrusion Detection System (CICIDS2017)

This script loads the raw CICIDS2017 dataset, explores its structure,
cleans anomalies, and prepares data for machine learning modeling.

Key Steps:
1. Load and combine all 7 CSV files
2. Understand the class distribution
3. Check data quality (missing values, data types)
4. Clean anomalies (infinite values, missing data)
5. Explore feature distributions and their security relevance
6. Generate visualizations
7. Save cleaned data for the next session
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import warnings

warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

# Adjust these paths to match your setup
DATA_RAW_DIR = Path('data/raw')
DATA_PROCESSED_DIR = Path('data/processed')
LOGS_DIR = Path('logs')

# Create output directories if they don't exist
DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# CSV files to load (in chronological order)
CSV_FILES = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-WorkingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

# ============================================================================
# STEP 1: LOAD THE DATA
# ============================================================================

print("=" * 80)
print("STEP 1: LOADING DATA")
print("=" * 80)

dataframes = []

for csv_file in CSV_FILES:
    filepath = DATA_RAW_DIR / csv_file
    
    if not filepath.exists():
        print(f"WARNING: File not found: {filepath}")
        continue
    
    print(f"Loading {csv_file}...", end=' ')
    
    # Load CSV
    df = pd.read_csv(filepath)
    
    # CRITICAL: Strip whitespace from column names
    # The CICIDS2017 dataset has leading/trailing spaces in column names!
    df.columns = df.columns.str.strip()
    
    dataframes.append(df)
    print(f"OK ({len(df)} rows, {len(df.columns)} columns)")

if not dataframes:
    raise FileNotFoundError(
        f"No CSV files found in {DATA_RAW_DIR}. "
        "Please check your dataset download."
    )

# Combine all dataframes
print(f"\nCombining {len(dataframes)} files...")
df = pd.concat(dataframes, ignore_index=True)

print(f"Combined dataset shape: {df.shape}")
print(f"  Rows (flows): {len(df):,}")
print(f"  Columns (features): {len(df.columns)}")

# Print first few rows
print("\nFirst 5 rows:")
print(df.head())

print("\nColumn names:")
print(df.columns.tolist())

# ============================================================================
# STEP 2: UNDERSTAND THE LABELS (CLASS DISTRIBUTION)
# ============================================================================

print("\n" + "=" * 80)
print("STEP 2: UNDERSTANDING THE LABELS")
print("=" * 80)

# The label column name varies; try common names
label_col = None
for possible_name in ['Label', ' Label', 'label', ' label', 'Class', ' Class']:
    if possible_name in df.columns:
        label_col = possible_name
        break

if label_col is None:
    print("Available columns:", df.columns.tolist())
    raise ValueError("Could not find label column in dataset")

print(f"Label column: '{label_col}'")

# Get value counts
label_counts = df[label_col].value_counts()
label_percentages = (df[label_col].value_counts(normalize=True) * 100).round(2)

print("\nClass Distribution (Raw Counts):")
print(label_counts)

print("\nClass Distribution (Percentages):")
for label, pct in label_percentages.items():
    print(f"  {label}: {pct:6.2f}%")

# Separate benign and attack classes
benign_count = label_counts.get('BENIGN', 0)
attack_count = df.shape[0] - benign_count
attack_ratio = (attack_count / df.shape[0] * 100)

print(f"\nBenign flows: {benign_count:,} ({benign_count/df.shape[0]*100:.2f}%)")
print(f"Attack flows: {attack_count:,} ({attack_ratio:.2f}%)")

if attack_ratio < 30:
    print(f"\nIMPORTANT: This dataset is IMBALANCED!")
    print(f"  - Only {attack_ratio:.1f}% are attacks")
    print(f"  - ML models need special handling for this (weights, resampling, metrics)")

# ============================================================================
# STEP 3: DATA QUALITY CHECK
# ============================================================================

print("\n" + "=" * 80)
print("STEP 3: DATA QUALITY CHECK")
print("=" * 80)

# Check data types
print("\nData Types:")
dtype_summary = df.dtypes.value_counts()
print(dtype_summary)

# Check for missing values
missing_counts = df.isnull().sum()
missing_total = missing_counts.sum()

if missing_total > 0:
    print(f"\nMissing Values (non-zero only):")
    print(missing_counts[missing_counts > 0])
else:
    print("\nMissing Values: NONE (excellent data quality)")

# Check for infinite values (common in numeric data)
print("\nChecking for infinite values...")
numeric_cols = df.select_dtypes(include=[np.number]).columns
inf_counts = {}

for col in numeric_cols:
    inf_count = np.isinf(df[col]).sum()
    if inf_count > 0:
        inf_counts[col] = inf_count

if inf_counts:
    print(f"Found {len(inf_counts)} columns with infinite values:")
    for col, count in sorted(inf_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {col}: {count} inf values ({count/len(df)*100:.2f}%)")
else:
    print("Infinite Values: NONE")

# Check for duplicate rows
duplicate_count = df.duplicated().sum()
print(f"\nDuplicate rows: {duplicate_count} ({duplicate_count/len(df)*100:.4f}%)")

# ============================================================================
# STEP 4: CLEAN THE DATA
# ============================================================================

print("\n" + "=" * 80)
print("STEP 4: DATA CLEANING")
print("=" * 80)

print(f"Starting with {len(df):,} rows")

# Replace infinite values with NaN
for col in numeric_cols:
    df.loc[np.isinf(df[col]), col] = np.nan

# Drop rows with ANY missing values
rows_before = len(df)
df = df.dropna()
rows_dropped = rows_before - len(df)

print(f"Dropped {rows_dropped:,} rows with missing/infinite values")
print(f"Remaining: {len(df):,} rows")

# ============================================================================
# STEP 5: EXPLORE KEY SECURITY-RELEVANT FEATURES
# ============================================================================

print("\n" + "=" * 80)
print("STEP 5: FEATURE ANALYSIS")
print("=" * 80)
print("Comparing key features between BENIGN and ATTACK traffic\n")

# Key features to analyze (security-relevant)
key_features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Flow IAT Mean',
]

# Verify these features exist (with possible whitespace issues)
available_features = []
for feature in key_features:
    # Try exact match and with spaces
    if feature in df.columns:
        available_features.append(feature)
    elif f' {feature}' in df.columns:
        available_features.append(f' {feature}')

if not available_features:
    print("WARNING: Key features not found. Using generic numeric columns instead.")
    available_features = numeric_cols[:8].tolist()

print(f"Analyzing {len(available_features)} features:\n")

# Create comparison table
comparison_data = []

for feature in available_features:
    if feature not in df.columns:
        continue
    
    benign_vals = df[df[label_col] == 'BENIGN'][feature]
    attack_vals = df[df[label_col] != 'BENIGN'][feature]
    
    print(f"Feature: {feature}")
    print(f"  Benign:  mean={benign_vals.mean():.2f}, std={benign_vals.std():.2f}")
    print(f"  Attack:  mean={attack_vals.mean():.2f}, std={attack_vals.std():.2f}")
    print()

# ============================================================================
# STEP 6: VISUALIZATIONS
# ============================================================================

print("\n" + "=" * 80)
print("STEP 6: GENERATING VISUALIZATIONS")
print("=" * 80)

# Visualization 1: Class Distribution
plt.figure(figsize=(10, 5))
label_counts.plot(kind='bar', color=['green', 'red'])
plt.title('Class Distribution: BENIGN vs ATTACK', fontsize=14, fontweight='bold')
plt.xlabel('Attack Type')
plt.ylabel('Count')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig(DATA_PROCESSED_DIR / '01_class_distribution.png', dpi=100, bbox_inches='tight')
print("Saved: 01_class_distribution.png")
plt.close()

# Visualization 2: Feature Distributions (Box Plots)
if available_features:
    fig, axes = plt.subplots(2, 4, figsize=(16, 8))
    axes = axes.flatten()
    
    for idx, feature in enumerate(available_features[:8]):
        if feature not in df.columns:
            continue
        
        ax = axes[idx]
        
        # Prepare data
        benign_data = df[df[label_col] == 'BENIGN'][feature]
        attack_data = df[df[label_col] != 'BENIGN'][feature]
        
        # Create box plot
        ax.boxplot([benign_data, attack_data], labels=['Benign', 'Attack'])
        ax.set_title(feature, fontweight='bold')
        ax.set_ylabel('Value')
        ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(DATA_PROCESSED_DIR / '02_feature_distributions.png', dpi=100, bbox_inches='tight')
    print("Saved: 02_feature_distributions.png")
    plt.close()

# Visualization 3: Correlation Heatmap
print("\nGenerating correlation matrix (this may take a moment)...")
corr_matrix = df[numeric_cols].corr()

plt.figure(figsize=(14, 12))
sns.heatmap(corr_matrix, cmap='coolwarm', center=0, square=True, 
            cbar_kws={'label': 'Correlation'}, vmin=-1, vmax=1)
plt.title('Feature Correlation Matrix', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(DATA_PROCESSED_DIR / '03_correlation_heatmap.png', dpi=100, bbox_inches='tight')
print("Saved: 03_correlation_heatmap.png")
plt.close()

# ============================================================================
# STEP 7: FEATURE STATISTICS SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("STEP 7: FEATURE STATISTICS")
print("=" * 80)

# Calculate discrimination power using Cohen's d (effect size)
print("\nFeature Discrimination Power (Cohen's d)")
print("  - Measures how well a feature separates benign from attack traffic")
print("  - Higher absolute d = better discrimination\n")

cohen_d_results = []

for feature in numeric_cols:
    benign_vals = df[df[label_col] == 'BENIGN'][feature]
    attack_vals = df[df[label_col] != 'BENIGN'][feature]
    
    # Cohen's d = (mean1 - mean2) / pooled_std
    mean_diff = benign_vals.mean() - attack_vals.mean()
    pooled_std = np.sqrt(
        ((len(benign_vals)-1)*benign_vals.std()**2 + 
         (len(attack_vals)-1)*attack_vals.std()**2) / 
        (len(benign_vals) + len(attack_vals) - 2)
    )
    
    if pooled_std > 0:
        cohens_d = mean_diff / pooled_std
    else:
        cohens_d = 0
    
    cohen_d_results.append({
        'Feature': feature,
        'Cohen_d': abs(cohens_d),
        'Mean_Diff': mean_diff
    })

# Sort by Cohen's d (descending)
cohen_d_df = pd.DataFrame(cohen_d_results).sort_values('Cohen_d', ascending=False)

print("Top 20 Most Discriminative Features:")
print(cohen_d_df.head(20).to_string(index=False))

# ============================================================================
# STEP 8: SAVE CLEANED DATA
# ============================================================================

print("\n" + "=" * 80)
print("STEP 8: SAVING CLEANED DATA")
print("=" * 80)

# Save cleaned CSV
output_csv = DATA_PROCESSED_DIR / 'CICIDS2017_combined_cleaned.csv'
df.to_csv(output_csv, index=False)
print(f"Saved cleaned data: {output_csv}")
print(f"  Size: {len(df):,} rows x {len(df.columns)} columns")
print(f"  Disk space: {output_csv.stat().st_size / 1e9:.2f} GB")

# Save summary report as text
summary_file = LOGS_DIR / 'session1_summary.txt'
with open(summary_file, 'w') as f:
    f.write("PROJECT 1, SESSION 1: DATA EXPLORATION SUMMARY\n")
    f.write("=" * 80 + "\n\n")
    
    f.write("DATASET OVERVIEW\n")
    f.write("-" * 80 + "\n")
    f.write(f"Total flows: {len(df):,}\n")
    f.write(f"Total features: {len(df.columns)}\n")
    f.write(f"Benign flows: {(df[label_col]=='BENIGN').sum():,}\n")
    f.write(f"Attack flows: {(df[label_col]!='BENIGN').sum():,}\n\n")
    
    f.write("CLASS DISTRIBUTION\n")
    f.write("-" * 80 + "\n")
    for label, count in label_counts.items():
        pct = count / len(df) * 100
        f.write(f"{label}: {count:,} ({pct:.2f}%)\n")
    f.write("\n")
    
    f.write("TOP 20 DISCRIMINATIVE FEATURES (Cohen's d)\n")
    f.write("-" * 80 + "\n")
    f.write(cohen_d_df.head(20).to_string(index=False))
    f.write("\n\n")
    
    f.write("DATA QUALITY METRICS\n")
    f.write("-" * 80 + "\n")
    f.write(f"Missing values: {df.isnull().sum().sum()}\n")
    f.write(f"Duplicate rows: {df.duplicated().sum()}\n")
    f.write(f"Memory usage: {df.memory_usage(deep=True).sum() / 1e9:.2f} GB\n")

print(f"Saved summary report: {summary_file}")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("SESSION 1 COMPLETE!")
print("=" * 80)
print(f"\nYou now have:")
print(f"  - Combined dataset: {len(df):,} network flows")
print(f"  - Cleaned data saved: data/processed/CICIDS2017_combined_cleaned.csv")
print(f"  - 3 visualizations: correlation heatmap, class distribution, feature distributions")
print(f"  - Summary report: logs/session1_summary.txt")
print(f"\nNext steps (Session 2):")
print(f"  - Build ML models (Random Forest, XGBoost)")
print(f"  - Implement train/test split with stratification")
print(f"  - Handle class imbalance")
print(f"  - Evaluate with security-relevant metrics")
```

### Step 3.2: Run the Script

```bash
# Make sure you're in the project root directory
# And your virtual environment is activated

python session1_exploration.py
```

**Expected output:**
```
================================================================================
STEP 1: LOADING DATA
================================================================================
Loading Monday-WorkingHours.pcap_ISCX.csv... OK (659,844 rows, 85 columns)
Loading Tuesday-WorkingHours.pcap_ISCX.csv... OK (567,498 rows, 85 columns)
...
Combined dataset shape: (2834214, 85)

================================================================================
STEP 2: UNDERSTANDING THE LABELS
================================================================================
Class Distribution (Raw Counts):
BENIGN      2273641
DoS Hulk      231073
...
```

**Output files created:**
- `data/processed/CICIDS2017_combined_cleaned.csv` - cleaned dataset
- `data/processed/01_class_distribution.png` - class distribution chart
- `data/processed/02_feature_distributions.png` - feature box plots
- `data/processed/03_correlation_heatmap.png` - correlation matrix
- `logs/session1_summary.txt` - text summary of findings

---

## Part 4: Understanding Your Results

### What Does Class Imbalance Mean?

When you see the class distribution, you'll notice something like:
- BENIGN: 80% of flows
- DoS attacks: 8% of flows
- Other attacks: 12% of flows

This is **class imbalance**, and it's a real-world problem in security. Why? Because in real networks, attacks ARE rare (hopefully). This creates challenges for ML:

| Problem | Impact | Solution |
|---------|--------|----------|
| ML model learns to always predict "benign" | High accuracy but misses attacks | Use class weights or resampling |
| Minority class ignored | Model performs poorly on attacks | Use stratified train/test split |
| Misleading metrics | Accuracy looks good but model is useless | Use precision, recall, F1, AUC-ROC |

You'll handle this in Session 2.

### Interpreting Feature Distributions

When you look at the box plots, you're comparing benign vs. attack for each feature:

**Example: Flow Duration**
- Benign traffic: varied durations (users browsing, working)
- DoS attacks: very short duration (floods then stops)
- Brute force: long duration (many login attempts)

These differences are what your ML model will learn.

### Cohen's d: The Discrimination Score

The summary report ranks features by Cohen's d, which measures how well a feature separates benign from attack:

- **|d| > 2.0**: Excellent discrimination (strong feature)
- **|d| 0.5-2.0**: Good discrimination (useful feature)
- **|d| < 0.5**: Poor discrimination (may be noise)

Features with high Cohen's d are the "smoking guns" of attack traffic.

---

## Part 5: Troubleshooting

### Problem: "FileNotFoundError: No CSV files found"

**Cause:** The script can't find the CICIDS2017 CSV files.

**Solution:**
1. Check that you downloaded the dataset to `data/raw/`
2. Verify the CSV file names match exactly
3. If using Kaggle, make sure you've extracted the ZIP file

```bash
# List files in your data/raw directory
ls -lh data/raw/

# Should show 7 files like:
# Monday-WorkingHours.pcap_ISCX.csv
# Tuesday-WorkingHours.pcap_ISCX.csv
# etc.
```

### Problem: "Could not find label column in dataset"

**Cause:** The label column has a different name than expected.

**Solution:**
1. Open one CSV file to check the actual column name:
```bash
head -1 data/raw/Monday-WorkingHours.pcap_ISCX.csv
```

2. Update the `label_col` variable in the script if needed:
```python
# Find the actual column name and update this line:
df.columns = df.columns.str.strip()
# Then update label_col = 'YourColumnName'
```

### Problem: "Memory Error" or "Out of Memory"

**Cause:** Your machine doesn't have enough RAM for all 2.8 million flows.

**Solution:** Process files one at a time:

```python
# In the script, modify Step 1 to process one file at a time:
for csv_file in CSV_FILES[:3]:  # Only Monday, Tuesday, Wednesday
    # rest of code
```

Or use chunking to process in batches:

```python
for csv_file in CSV_FILES:
    for chunk in pd.read_csv(filepath, chunksize=100000):
        # process chunk
        pass
```

### Problem: Column names don't match

**Cause:** CICIDS2017 has leading/trailing spaces in column names.

**Solution:** The script already handles this with:
```python
df.columns = df.columns.str.strip()
```

If issues persist, print all column names:
```python
for i, col in enumerate(df.columns):
    print(f"{i}: '{col}'")
```

### Problem: "The file is too large to open"

**Cause:** Individual CSV files are 1-3 GB.

**Solution:** Use pandas efficiently:
```bash
# Count rows without loading all into memory
wc -l data/raw/Monday-WorkingHours.pcap_ISCX.csv

# Use low_memory=False to avoid mixed-type warnings
df = pd.read_csv(filepath, low_memory=False)
```

---

## Part 6: Key Concepts Glossary

| Term | Definition | Security Relevance |
|------|-----------|-------------------|
| **Network Flow** | Bidirectional communication between two IP addresses (source→dest) | Fundamental unit of network analysis; each flow has source IP, port, destination IP, port |
| **IDS/NIDS** | Intrusion Detection System / Network IDS; monitors network for attacks | NIDS watches network flows; compares to signatures (traditional) or learns anomalies (ML) |
| **Signature-based Detection** | Flag traffic matching known attack patterns (like antivirus) | Fast and accurate for known attacks; fails on zero-days |
| **Anomaly-based Detection** | Flag traffic that deviates from normal baseline; learns "normal" | Can catch zero-days; requires good training on benign traffic |
| **Zero-day Attack** | Previously unknown vulnerability; no public signature exists | This is where ML IDS shines - detects anomalies even without known signature |
| **Class Imbalance** | Unequal distribution of classes (80% benign, 20% attack) | Model can bias toward majority class; need special metrics |
| **Cohen's d** | Effect size; measures how well two groups separate (here: benign vs attack) | d=0: no difference, d=2: strong separation |
| **DoS/DDoS** | Denial of Service / Distributed DoS; flood target with traffic to disable | Common attack; creates obvious patterns (high packet rates) |
| **Port Scan** | Attacker systematically probes network to find open services | Reconnaissance step; distinct network signature |
| **C2 Traffic** | Command & Control; attacker remote-controls compromised systems | Botnet communication; often low-bandwidth, periodic patterns |
| **MITRE ATT&CK** | Standardized framework of real-world attack techniques | Reference for understanding what attacks we're detecting |
| **Feature Engineering** | Creating new features from raw data to improve ML | Extract domain knowledge about network attacks into features |
| **SOC** | Security Operations Center; team monitoring security 24/7 | Your IDS feeds alerts to SOC analysts |
| **Stratification** | Keep class proportions when splitting train/test | Important for imbalanced datasets; ensures representative test set |
| **ROC-AUC** | Receiver Operating Characteristic - Area Under Curve; metric for binary classification | Better than accuracy for imbalanced classes |
| **Precision/Recall** | Precision: of detected attacks, how many correct? Recall: of all attacks, how many detected? | Both matter in security: catch attacks (recall) AND avoid false alarms (precision) |

---

## Part 7: Next Session Preview

### Session 2: Building Your First Models

In the next session, you'll:

1. **Feature Engineering**
   - Select high-discrimination features using Cohen's d
   - Scale/normalize numeric features
   - Encode categorical features

2. **Train/Test Split**
   - Use stratified split to keep class proportions
   - Protect against data leakage

3. **Build ML Models**
   - Random Forest: fast, interpretable, handles imbalance
   - XGBoost: state-of-the-art gradient boosting
   - Baseline comparison: Logistic Regression

4. **Handle Class Imbalance**
   - Class weights in random forest
   - SMOTE (Synthetic Minority Over-sampling)
   - Compare effectiveness

5. **Evaluate with Security Metrics**
   - Accuracy: how often correct?
   - Precision: false alarm rate?
   - Recall: attack detection rate?
   - F1-Score: harmonic mean
   - ROC-AUC: threshold-independent
   - Confusion Matrix: where does model fail?

6. **Model Comparison**
   - Which model catches most attacks?
   - Which has fewest false alarms?
   - Speed/accuracy tradeoff?

**Why this matters:** Different attack types need different detection strategies. Your model will learn to distinguish brute force from DDoS from port scans automatically.

---

## Session 1 Checklist

Before moving to Session 2, verify you've completed:

- [ ] Created project directory structure (`data/raw`, `data/processed`, `notebooks`, `models`, `logs`)
- [ ] Set up Python virtual environment and installed dependencies
- [ ] Downloaded CICIDS2017 dataset from UNB or Kaggle
- [ ] Created `session1_exploration.py` script
- [ ] Ran the script successfully
- [ ] Generated 3 visualizations (class distribution, feature distributions, correlation heatmap)
- [ ] Reviewed `logs/session1_summary.txt` summary report
- [ ] Understood what class imbalance means and why it matters
- [ ] Identified top discriminative features (Cohen's d > 2.0)
- [ ] Reviewed the glossary and understand key cybersecurity terms
- [ ] Ready for Session 2: Building Models

---

## Additional Resources

### Academic Papers
- Original CICIDS2017 paper: "Toward Generating a Dataset for Anomaly Detection in Networks" (CIC, 2018)
- IDS overview: "A Survey of Intrusion Detection Systems in Cloud" (IEEE, 2016)
- ML for security: "Machine Learning for Cybersecurity" by Ritchie King

### Datasets
- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- Kaggle copy: https://www.kaggle.com/cicdataset/cicids2017
- Other IDS datasets: NSL-KDD, KDDCUP99, UNSW-NB15

### Tools & Standards
- MITRE ATT&CK: https://attack.mitre.org (attack taxonomy)
- Snort/Suricata: traditional signature-based NIDS
- Zeek (Bro): network analysis framework

### Security Concepts
- Network protocols: TCP/IP, DNS, HTTP/HTTPS
- Attack types: OWASP Top 10, CWE/CVSS
- Defense-in-depth: layered security approach

---

## Summary

You now understand:

1. **The big picture:** Building an ML-based NIDS to detect both known and unknown attacks
2. **The data:** CICIDS2017 has 2.8M flows with 7 attack types + benign traffic
3. **The challenge:** Class imbalance (rare attacks = rare in data too)
4. **Feature relevance:** Some features (Flow Duration, Packet counts) distinguish attacks well
5. **Next steps:** Build models that learn these patterns automatically

Session 1 is about **understanding the problem**. Sessions 2-4 are about **solving it**.

Good luck, and welcome to AI-powered cybersecurity!

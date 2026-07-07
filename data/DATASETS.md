# Datasets — Training the Email Classifier

The classifier uses a layered dataset strategy. Each tier adds more training
examples, improving detection accuracy.

---

## Current Bundled Data (ships with project)

| File | Rows | Source | Notes |
|---|---|---|---|
| `data/seed_dataset.json` | 560 | Manual + CEAS_08 sample + kuladeep sample | Pre-merged, ready to use |
| `data/ceas08_sample.csv` | 350 | CEAS_08 (2008 Spam Conference) | 175 safe + 175 phishing |
| `data/kuladeep_sample.csv` | 51 | Synthetic phishing examples | 25 phishing + 26 legitimate |

**Estimated accuracy with bundled data: ~88%** 

---

## Tier 2 — Full CEAS_08 (~68 MB, automatic download)

The full CEAS_08 dataset has ~33,000 labeled emails from a real 2008 spam
challenge. It's publicly mirrored on HuggingFace.

**One command:**
```
python data/download_and_train.py --full-ceas --retrain
```

This streams up to 3,000 additional balanced rows directly without saving
the full file. To also save the full CSV locally:
```
python data/download_and_train.py --full-ceas --save-ceas --retrain
```

**Expected accuracy after Tier 2: ~90–92%**

---

## Tier 3 — Full kuladeep19 Dataset (manual Kaggle download, ~10,000 rows)

This is a synthetically generated dataset with diverse phishing types:
credential harvesting, BEC, lottery scams, delivery scams, etc.

### Step-by-step:

1. **Create a free Kaggle account** at https://www.kaggle.com (if you don't have one)

2. **Go to the dataset page:**
   https://www.kaggle.com/datasets/kuladeep19/phishing-and-legitimate-emails-dataset

3. **Click "Download"** — downloads a ZIP file

4. **Extract the ZIP** and find the CSV file inside

5. **Rename and place it:**
   ```
   data/phishing_emails.csv
   ```

6. **Retrain:**
   ```
   python data/download_and_train.py --retrain
   ```

### Alternative: Kaggle CLI

```bash
pip install kaggle

# Set up API token: download kaggle.json from your Kaggle account settings
# and place it at C:\Users\<you>\.kaggle\kaggle.json

kaggle datasets download -d kuladeep19/phishing-and-legitimate-emails-dataset -p data/ --unzip
rename data\phishing_and_legitimate_emails.csv data\phishing_emails.csv
python data\download_and_train.py --retrain
```

**Expected accuracy after Tier 3: ~92–94%**

---

## Tier 3b — Full CEAS_08 from Kaggle (35,000+ rows)

The full original dataset is also on Kaggle:
https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset

```bash
kaggle datasets download -d naserabdullahalam/phishing-email-dataset -p data/ --unzip
# Look for CEAS_08.csv in the extracted files
python data\download_and_train.py --retrain
```

---

## Accuracy Estimates by Dataset Size

| Training Examples | Estimated CV Accuracy | Notes |
|---|---|---|
| 42 (original) | ~63% | Overfit on tiny set — real accuracy worse |
| 560 (bundled) | **~88%** | Current state after setup |
| ~3,500 (+ Tier 2) | ~90–92% | Full CEAS_08 download |
| ~13,500 (+ Tier 3) | ~92–94% | + Full kuladeep19 |
| ~40,000+ (all sources) | ~93–96% | All datasets combined |

> These are **cross-validation estimates** on the training distribution.
> Real-world accuracy on novel phishing emails may be lower; the heuristic
> scoring (URL analysis, header analysis, keyword matching) runs alongside
> the ML classifier and compensates for model uncertainty.

---

## Important Notes

- **Never add confidential emails** to the training data.
- All examples are deduplicated by MD5 hash of the email body before merging.
- Each class is capped at 3,000 examples by default (configurable in `download_and_train.py`).
- After any retrain, the server must be **restarted** for the new model to load (or hit the `/api/feedback` submit endpoint to trigger a retrain via the UI).

---

## Running the Trainer

```
# See all options:
python data/download_and_train.py --help

# Retrain on bundled data only:
python data/download_and_train.py --retrain

# Download + retrain with full CEAS_08:
python data/download_and_train.py --full-ceas --retrain

# Show Kaggle download instructions:
python data/download_and_train.py --help-kaggle
```

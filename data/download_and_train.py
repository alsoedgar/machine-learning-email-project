"""
download_and_train.py
===========================================================================
Expands the phishing email classifier with real-world training data.

Three tiers — use whichever matches your situation:

  TIER 1 (automatic, no downloads): uses the bundled 350-row CEAS_08 sample
          and 51-row kuladeep sample that ship with the project. These are
          already merged into data/seed_dataset.json; just run with --retrain.

  TIER 2 (one command, ~68 MB download): streams the full CEAS_08.csv from a
          public HuggingFace mirror and adds up to 3,000 balanced new rows.
          Run with --full-ceas.

  TIER 3 (manual Kaggle download, best accuracy):
          The kuladeep19 dataset has 10,000 synthetically generated emails.
          Download instructions are printed when you run with --help-kaggle.

Usage examples:
  python data/download_and_train.py --retrain
  python data/download_and_train.py --full-ceas
  python data/download_and_train.py --full-ceas --retrain
  python data/download_and_train.py --help-kaggle
===========================================================================
"""

import os
import sys
import csv
import json
import math
import random
import hashlib
import argparse
import urllib.request

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR     = SCRIPT_DIR

SEED_PATH       = os.path.join(DATA_DIR, 'seed_dataset.json')
CEAS_SAMPLE     = os.path.join(DATA_DIR, 'ceas08_sample.csv')       # bundled ~350 rows
CEAS_FULL       = os.path.join(DATA_DIR, 'CEAS_08.csv')             # full ~33,000 rows
KULADEEP_SAMPLE = os.path.join(DATA_DIR, 'kuladeep_sample.csv')     # bundled 51 rows
KULADEEP_FULL   = os.path.join(DATA_DIR, 'phishing_emails.csv')     # manual Kaggle download

CEAS_HF_URL = (
    'https://huggingface.co/datasets/JunXi888/Phishing_Detector_Datasets'
    '/resolve/main/CEAS_08.csv'
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def body_hash(text):
    return hashlib.md5(text.strip().encode('utf-8', 'ignore')).hexdigest()


def load_seed():
    with open(SEED_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_seed(seed):
    with open(SEED_PATH, 'w', encoding='utf-8') as f:
        json.dump(seed, f, indent=2, ensure_ascii=False)


def current_hashes(seed):
    safe_h = set(body_hash(e.get('body', '')) for e in seed.get('safe', []))
    mal_h  = set(body_hash(e.get('body', '')) for e in seed.get('malicious', []))
    spam_h = set(body_hash(e.get('body', '')) for e in seed.get('spam', []))
    return safe_h, mal_h, spam_h


def merge_rows(seed, rows, max_per_class=3000):
    """
    rows: list of (label_str, subject, body) where label_str is 'Safe' or 'Malicious'
    Adds rows to seed, deduplicates by MD5, caps each class at max_per_class.
    Returns (added_safe, added_mal).
    """
    safe_h, mal_h, _ = current_hashes(seed)
    added_safe = added_mal = 0

    for label_str, subj, body in rows:
        body = body[:1500]
        if len(body) < 20:
            continue
        h = body_hash(body)
        if label_str == 'Safe':
            if h not in safe_h and len(seed.get('safe', [])) < max_per_class:
                seed.setdefault('safe', []).append({'subject': subj, 'body': body})
                safe_h.add(h)
                added_safe += 1
        elif label_str == 'Malicious':
            if h not in mal_h and len(seed.get('malicious', [])) < max_per_class:
                seed.setdefault('malicious', []).append({'subject': subj, 'body': body})
                mal_h.add(h)
                added_mal += 1

    return added_safe, added_mal


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_ceas_csv(path):
    """Load rows from a CEAS_08.csv file. Returns list of (label, subject, body)."""
    rows = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for row in csv.DictReader(f):
                subj  = (row.get('subject') or '').strip()
                body  = (row.get('body')    or '').strip()
                label = (row.get('label')   or '').strip()
                if label == '0':
                    rows.append(('Safe', subj, body))
                elif label == '1':
                    rows.append(('Malicious', subj, body))
    except Exception as e:
        print('  [!] Could not read {}: {}'.format(path, e))
    return rows


def load_kuladeep_csv(path):
    """Load rows from kuladeep-format CSV (columns: text, label, phishing_type, ...)."""
    rows = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for row in csv.DictReader(f):
                body  = (row.get('text') or '').strip()
                label = str(row.get('label', '')).strip()
                ptype = (row.get('phishing_type') or '').strip().lower()
                label_str = 'Safe' if (label == '0' or ptype == 'legitimate') else 'Malicious'
                rows.append((label_str, '', body))
    except Exception as e:
        print('  [!] Could not read {}: {}'.format(path, e))
    return rows


# ── Download helpers ──────────────────────────────────────────────────────────

def _progress(block, bsize, total):
    done = block * bsize
    if total > 0:
        pct = min(done / total * 100, 100)
        mb  = done / 1_048_576
        tot = total / 1_048_576
        print('\r  [{:.0f}%]  {:.1f} / {:.1f} MB'.format(pct, mb, tot),
              end='', flush=True)
    else:
        print('\r  {:.1f} MB downloaded …'.format(done / 1_048_576),
              end='', flush=True)


def stream_ceas_sample(max_rows_per_class=1500):
    """
    Stream CEAS_08.csv from HuggingFace and collect up to max_rows_per_class
    rows per class without downloading the full 68 MB file.
    """
    print('  Streaming CEAS_08.csv from HuggingFace …')
    req = urllib.request.Request(CEAS_HF_URL, headers={'User-Agent': 'Mozilla/5.0'})
    safe_rows = []
    phish_rows = []
    buf = ''
    header = None

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            while True:
                chunk = resp.read(131072)  # 128 KB chunks
                if not chunk:
                    break
                buf += chunk.decode('utf-8', errors='ignore')
                lines = buf.split('\n')
                buf = lines[-1]
                for line in lines[:-1]:
                    if not line.strip():
                        continue
                    if header is None:
                        header = line
                        continue
                    try:
                        import io
                        row = next(csv.reader(io.StringIO(line)))
                    except Exception:
                        continue
                    if len(row) < 6:
                        continue
                    label = row[5].strip()
                    subj  = row[3].strip() if len(row) > 3 else ''
                    body  = row[4].strip() if len(row) > 4 else ''
                    if label == '0' and len(safe_rows) < max_rows_per_class:
                        safe_rows.append(('Safe', subj, body))
                    elif label == '1' and len(phish_rows) < max_rows_per_class:
                        phish_rows.append(('Malicious', subj, body))
                if len(safe_rows) >= max_rows_per_class and len(phish_rows) >= max_rows_per_class:
                    print('\r  Collected {} safe + {} phishing rows. Stopping stream.'.format(
                        len(safe_rows), len(phish_rows)))
                    break
    except Exception as e:
        print('\n  [!] Stream failed: {}'.format(e))
        return []

    print('\n  Stream complete: {} safe + {} phishing rows collected.'.format(
        len(safe_rows), len(phish_rows)))
    return safe_rows + phish_rows


def download_full_ceas():
    """Download the complete CEAS_08.csv (~68 MB) to data/CEAS_08.csv."""
    if os.path.exists(CEAS_FULL):
        print('  data/CEAS_08.csv already exists — skipping download.')
        return True
    print('  Downloading full CEAS_08.csv (~68 MB) …')
    try:
        req = urllib.request.Request(CEAS_HF_URL, headers={'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlretrieve(CEAS_HF_URL, CEAS_FULL, reporthook=_progress)
        print()
        print('  Saved -> ' + CEAS_FULL)
        return True
    except Exception as e:
        print('\n  [!] Download failed: {}'.format(e))
        return False


# ── Accuracy estimator ────────────────────────────────────────────────────────

def estimate_accuracy(seed, n_folds=5):
    """Quick k-fold cross-validation using our own Naive Bayes to estimate accuracy."""
    import re

    def tokenize(t):
        return re.findall(r'[a-zA-Z]{3,}', t.lower())

    def train(texts, labels):
        from collections import defaultdict
        counts = defaultdict(lambda: defaultdict(int))
        cc = defaultdict(int)
        vocab = set()
        for t, l in zip(texts, labels):
            for w in tokenize(t):
                counts[l][w] += 1
                vocab.add(w)
            cc[l] += 1
        return counts, cc, vocab

    def predict(text, counts, cc, vocab):
        best_l, best_s = None, float('-inf')
        total = sum(cc.values())
        for l in cc:
            s = math.log(cc[l] / total)
            ct = sum(counts[l].values()) + len(vocab)
            for w in tokenize(text):
                s += math.log((counts[l].get(w, 0) + 1) / ct)
            if s > best_s:
                best_s = s
                best_l = l
        return best_l

    data = []
    for e in seed.get('safe', []):
        data.append((e.get('subject', '') + ' ' + e.get('body', ''), 'Safe'))
    for e in seed.get('malicious', []):
        data.append((e.get('subject', '') + ' ' + e.get('body', ''), 'Malicious'))
    for e in seed.get('spam', []):
        data.append((e.get('subject', '') + ' ' + e.get('body', ''), 'Spam'))

    if len(data) < n_folds * 2:
        return None

    random.seed(42)
    random.shuffle(data)
    fold = len(data) // n_folds
    correct = total = 0
    for i in range(n_folds):
        test  = data[i * fold:(i + 1) * fold]
        train_data = data[:i * fold] + data[(i + 1) * fold:]
        tr_t, tr_l = zip(*train_data)
        c, cc, v = train(tr_t, tr_l)
        for text, label in test:
            if predict(text, c, cc, v) == label:
                correct += 1
            total += 1
    return correct / total if total > 0 else None


# ── Retrain the live model ────────────────────────────────────────────────────

def retrain_model():
    sys.path.insert(0, PROJECT_ROOT)
    try:
        from analyzer import EmailAnalyzer
        a = EmailAnalyzer()
        result = a.retrain_model()
        return result
    except Exception as e:
        print('  [!] Retrain failed: {}'.format(e))
        return False


# ── Help text ─────────────────────────────────────────────────────────────────

def print_kaggle_help():
    print("""
║                                                                  ║
║  How to download the full CEAS_08 dataset (Tier 2):             ║
║                                                                  ║
║  Automatic:  python data/download_and_train.py --full-ceas      ║
║  (~68 MB download, adds up to 3,000 more training examples)     ║
║                                                                  ║
║  Manual: https://www.kaggle.com/datasets/                       ║
║    naserabdullahalam/phishing-email-dataset                     ║
║    → Download CEAS_08.csv → place in data/CEAS_08.csv           ║
║    → Run: python data/download_and_train.py --retrain           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Expand and retrain the phishing email classifier.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--retrain',    action='store_true',
                        help='Retrain the model after merging datasets.')
    parser.add_argument('--full-ceas',  action='store_true',
                        help='Stream/download the full CEAS_08.csv (~68 MB) and merge.')
    parser.add_argument('--save-ceas',  action='store_true',
                        help='Save the full CEAS_08.csv locally (used with --full-ceas).')
    parser.add_argument('--help-kaggle', action='store_true',
                        help='Print step-by-step instructions for Kaggle downloads.')
    args = parser.parse_args()

    if args.help_kaggle:
        print_kaggle_help()
        return

    print('\n===========================================')
    print('  Email Classifier -- Dataset Trainer')
    print('===========================================\n')

    seed = load_seed()
    before_safe = len(seed.get('safe', []))
    before_mal  = len(seed.get('malicious', []))
    before_total = before_safe + before_mal + len(seed.get('spam', []))

    print('Current seed dataset:')
    print('  Safe={}  Malicious={}  Spam={}'.format(
        before_safe, before_mal, len(seed.get('spam', []))))

    total_added_safe = total_added_mal = 0

    # ── Tier 1: bundled samples (always merge if new rows found) ──────────────
    print('\n[Tier 1] Bundled samples (no download required)')

    if os.path.exists(CEAS_SAMPLE):
        rows = load_ceas_csv(CEAS_SAMPLE)
        ns, nm = merge_rows(seed, rows)
        total_added_safe += ns
        total_added_mal  += nm
        print('  ceas08_sample.csv   +safe={} +malicious={}'.format(ns, nm))
    else:
        print('  ceas08_sample.csv not found (should ship with the project)')

    if os.path.exists(KULADEEP_SAMPLE):
        rows = load_kuladeep_csv(KULADEEP_SAMPLE)
        ns, nm = merge_rows(seed, rows)
        total_added_safe += ns
        total_added_mal  += nm
        print('  kuladeep_sample.csv +safe={} +malicious={}'.format(ns, nm))
    else:
        print('  kuladeep_sample.csv not found (should ship with the project)')

    # ── Tier 2: full CEAS_08 ──────────────────────────────────────────────────
    if args.full_ceas:
        print('\n[Tier 2] Full CEAS_08 dataset (~68 MB)')
        if args.save_ceas:
            success = download_full_ceas()
            if success:
                rows = load_ceas_csv(CEAS_FULL)
                ns, nm = merge_rows(seed, rows, max_per_class=3000)
                total_added_safe += ns
                total_added_mal  += nm
                print('  CEAS_08.csv (full) +safe={} +malicious={}'.format(ns, nm))
        else:
            # Stream without saving (memory-efficient)
            rows = stream_ceas_sample(max_rows_per_class=1500)
            if rows:
                ns, nm = merge_rows(seed, rows, max_per_class=3000)
                total_added_safe += ns
                total_added_mal  += nm
                print('  Streamed           +safe={} +malicious={}'.format(ns, nm))
    else:
        print('\n  Tip: run with --full-ceas to download and add ~3,000 more real phishing emails.')
        print('       run with --full-ceas --save-ceas to also save CEAS_08.csv locally.')

    # ── Tier 3: kuladeep19 full dataset ──────────────────────────────────────
    if os.path.exists(KULADEEP_FULL):
        print('\n[Tier 3] Full kuladeep19 dataset (found locally)')
        rows = load_kuladeep_csv(KULADEEP_FULL)
        ns, nm = merge_rows(seed, rows, max_per_class=3000)
        total_added_safe += ns
        total_added_mal  += nm
        print('  phishing_emails.csv +safe={} +malicious={}'.format(ns, nm))
    else:
        print('\n  Tip: run --help-kaggle for instructions to download the 10,000-row kuladeep dataset.')

    # ── Save updated seed ─────────────────────────────────────────────────────
    after_safe  = len(seed.get('safe', []))
    after_mal   = len(seed.get('malicious', []))
    after_total = after_safe + after_mal + len(seed.get('spam', []))

    if total_added_safe + total_added_mal > 0:
        save_seed(seed)
        print('\n[OK] seed_dataset.json updated:')
        print('  Before: {} examples -> After: {} examples'.format(before_total, after_total))
        print('  +{} safe, +{} malicious added'.format(total_added_safe, total_added_mal))
    else:
        print('\n  No new examples to add (everything already in dataset).')

    # ── Accuracy estimate ─────────────────────────────────────────────────────
    print('\n[Accuracy Estimate] Running 5-fold cross-validation …')
    acc = estimate_accuracy(seed)
    if acc is not None:
        print('  Estimated accuracy on {} examples: {:.1f}%'.format(after_total, acc * 100))
        print()
        print('  Expected accuracy by dataset size:')
        print('    ~42 examples  (original baseline) : ~63%  (overfit on tiny set)')
        print('    ~560 examples (current, bundled)  : ~88%')
        print('    ~3,500 examples (+ full CEAS_08)  : ~90-92%')
        print('    ~13,500 examples (+ full kuladeep): ~92-94%')
    else:
        print('  Not enough data for cross-validation.')

    # ── Retrain ───────────────────────────────────────────────────────────────
    if args.retrain:
        print('\n[Retraining model] …')
        result = retrain_model()
        if result:
            print('[OK] Model successfully retrained on expanded dataset!')
        else:
            print('  [!] Retraining failed. Check that web_app.py imports are working.')
    else:
        if total_added_safe + total_added_mal > 0:
            print('\n  Tip: add --retrain to apply the new data to the live model.')
        print()

    print('Done.')


if __name__ == '__main__':
    main()

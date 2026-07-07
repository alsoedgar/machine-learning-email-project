import re
import math
import os
import json
import csv
from bs4 import BeautifulSoup



class NaiveBayesClassifier:
    """A pure-Python text classifier using Naive Bayes bag-of-words (Safe, Spam, Malicious)."""
    def __init__(self):
        self.vocabulary = set()
        self.class_counts = {"Safe": 0, "Spam": 0, "Malicious": 0}
        self.word_counts = {"Safe": {}, "Spam": {}, "Malicious": {}}
        self.total_words = {"Safe": 0, "Spam": 0, "Malicious": 0}
        
    def _tokenize(self, text):
        """Simplistic tokenizer: strips HTML tags, lowercase, splits into alphanumeric words > 2 chars."""
        # Sanitize data: remove HTML tags using a regex to reduce training noise
        text = re.sub(r'<[^>]*>', ' ', text)
        text = text.lower()
        words = re.findall(r'[a-z0-9]{3,}', text)
        
        # Generate bigrams to capture phrase context (e.g. "action required")
        bigrams = []
        for i in range(len(words) - 1):
            bigrams.append(f"{words[i]}_{words[i+1]}")
            
        return words + bigrams

    def train(self, emails, labels):
        self.__init__()
        for email_text, label in zip(emails, labels):
            if label not in self.class_counts:
                self.class_counts[label] = 0
                self.word_counts[label] = {}
                self.total_words[label] = 0
            self.class_counts[label] += 1
            words = self._tokenize(email_text)
            for w in words:
                self.vocabulary.add(w)
                self.word_counts[label][w] = self.word_counts[label].get(w, 0) + 1
                self.total_words[label] += 1
                
    def predict(self, text):
        words = self._tokenize(text)
        total_emails = sum(self.class_counts.values())
        if total_emails == 0:
            return "Safe", 0.5, {"Safe": 0.5, "Spam": 0.25, "Malicious": 0.25}
            
        priors = {}
        for cls in ["Safe", "Spam", "Malicious"]:
            prior = self.class_counts.get(cls, 0) / total_emails
            if prior == 0:
                prior = 0.01
            priors[cls] = prior
            
        log_probs = {}
        for cls in ["Safe", "Spam", "Malicious"]:
            log_probs[cls] = math.log(priors[cls])
            
        vocab_size = len(self.vocabulary)
        
        for w in words:
            for cls in ["Safe", "Spam", "Malicious"]:
                word_count = self.word_counts.get(cls, {}).get(w, 0)
                total_cls_words = self.total_words.get(cls, 0)
                
                p_w_cls = (word_count + 1) / (total_cls_words + vocab_size + 1)
                log_probs[cls] += math.log(p_w_cls)
                
        # Safe normalized probability calculations (softmax exponentiation)
        max_log = max(log_probs.values())
        exp_probs = {cls: math.exp(max(-50, min(50, log_p - max_log))) for cls, log_p in log_probs.items()}
        sum_exp = sum(exp_probs.values())
        probs = {cls: exp_probs[cls] / sum_exp if sum_exp > 0 else 0.33 for cls in ["Safe", "Spam", "Malicious"]}
        
        pred_class = max(probs, key=probs.get)
        confidence = probs[pred_class]
        
        return pred_class, confidence, probs

    def save(self, filepath):
        state = {
            'vocabulary': list(self.vocabulary),
            'class_counts': self.class_counts,
            'word_counts': self.word_counts,
            'total_words': self.total_words
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)

    def load(self, filepath):
        if not os.path.exists(filepath):
            return False
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                state = json.load(f)
            self.vocabulary = set(state['vocabulary'])
            self.class_counts = state['class_counts']
            self.word_counts = state['word_counts']
            self.total_words = state['total_words']
            return True
        except Exception:
            return False

    def train_on_feedback(self, feedback_csv_path, model_path, seed_emails, seed_labels):
        if not os.path.exists(feedback_csv_path):
            return False
            
        emails = []
        labels = []
        
        # Access control: Restrict file permissions locally on POSIX systems
        try:
            if hasattr(os, 'chmod'):
                os.chmod(feedback_csv_path, 0o600)
        except Exception:
            pass

        try:
            with open(feedback_csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                required_cols = {'body_text', 'subject', 'human_verdict'}
                if not required_cols.issubset(set(reader.fieldnames or [])):
                    return False  # Validation check failed (corrupted or tampered file schema)
                for row in reader:
                    verdict = row['human_verdict']
                    if verdict not in {"Safe", "Spam", "Malicious"}:
                        continue  # Validation of label class integrity
                    cleaned_body = row['body_text'].replace(' [NEWLINE] ', '\n')
                    emails.append(row['subject'] + "\n" + cleaned_body)
                    labels.append(verdict)
        except Exception:
            return False
            
        if not emails:
            return False
            
        all_emails = seed_emails + emails
        all_labels = seed_labels + labels
        
        self.train(all_emails, all_labels)
        self.save(model_path)
        return True
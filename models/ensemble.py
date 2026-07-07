class HybridPhishingClassifier:
    """Combines text-based Naive Bayes probabilities with metadata and link heuristic features."""
    
    def __init__(self, text_classifier=None):
        self.text_classifier = text_classifier

    def predict(self, text, metadata_features):
        """
        Combines Naive Bayes text probabilities with extracted metadata features.
        
        Args:
            text (str): Email subject + body text.
            metadata_features (dict): Dictionary of extracted metadata indicators.
            
        Returns:
            tuple: (prediction_class, confidence, probabilities_dict)
        """
        # 1. Fetch text-based Naive Bayes probabilities
        if self.text_classifier:
            text_pred, text_conf, text_probs = self.text_classifier.predict(text)
        else:
            text_probs = {"Safe": 0.6, "Spam": 0.2, "Malicious": 0.2}
            
        probs = text_probs.copy()
        
        # 2. Extract metadata anomaly flags
        brand_mismatch = metadata_features.get('display_brand_mismatch', 0.0)
        reply_mismatch = metadata_features.get('reply_to_mismatch', 0.0)
        network_anomaly = metadata_features.get('origin_network_anomaly', 0.0)
        urgency = metadata_features.get('suspicious_subject_urgency', 0.0)
        
        # 3. Apply heuristic boosts to the Malicious probability weight
        boost = 0.0
        if brand_mismatch > 0.0:
            boost += 0.45  # High-risk: Brand keyword in display name but domain mismatches
        if network_anomaly > 0.0:
            boost += 0.50  # High-risk: Origin SMTP server geolocates to Nigeria/high-risk block
        if reply_mismatch > 0.0:
            boost += 0.25  # Medium-risk: From address domain differs from Reply-To domain
        if urgency > 0.0:
            boost += 0.15  # Low-medium risk: Subject line indicates deadline pressure
            
        if boost > 0.0:
            # Shift weight from 'Safe' to 'Malicious'
            reduction = min(probs['Safe'], boost)
            probs['Safe'] -= reduction
            probs['Malicious'] += reduction
            
            # Re-normalize probabilities
            total = sum(probs.values())
            if total > 0:
                probs = {cls: val / total for cls, val in probs.items()}
                
        # 4. Resolve final prediction class
        # If malicious probability is at least 50% due to text or metadata boost, classify as Malicious
        if probs['Malicious'] >= 0.50:
            pred_class = "Malicious"
        elif probs['Spam'] > probs['Safe'] and probs['Spam'] > probs['Malicious']:
            pred_class = "Spam"
        elif probs['Safe'] > probs['Malicious']:
            pred_class = "Safe"
        else:
            pred_class = "Malicious"
            
        confidence = probs[pred_class]
        return pred_class, confidence, probs
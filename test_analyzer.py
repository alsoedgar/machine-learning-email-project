import unittest
import os
import json
import csv
import shutil
from analyzer import defang_url, EmailParser, HeuristicsAnalyzer, NaiveBayesClassifier, EmailAnalyzer

class TestEmailAnalyzerCore(unittest.TestCase):
    def setUp(self):
        # Create a temp directory for test files
        self.test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_temp")
        os.makedirs(self.test_dir, exist_ok=True)
        self.model_path = os.path.join(self.test_dir, "test_model.json")
        self.feedback_csv_path = os.path.join(self.test_dir, "test_feedback.csv")

    def tearDown(self):
        # Clean up temp directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_defang_url(self):
        # Standard HTTPS URL
        self.assertEqual(defang_url("https://bit.ly/xyz"), "hxxps://bit[.]ly/xyz")
        # Standard HTTP URL
        self.assertEqual(defang_url("http://google.com"), "hxxp://google[.]com")
        # Empty input
        self.assertEqual(defang_url(""), "")
        # Query parameters and path
        self.assertEqual(defang_url("https://example.com/path/to/file.html?q=1.2"), "hxxps://example[.]com/path/to/file.html?q=1.2")

    def test_email_parsing(self):
        raw_email = (
            "From: Alice <alice@safe-company.com>\n"
            "To: Bob <bob@example.com>\n"
            "Subject: Urgent security update required\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=\"boundary-string\"\n\n"
            "--boundary-string\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            "<html><body>\n"
            "Please click this link: <a href=\"https://malicious-domain.xyz/verify\">Confirm account</a><br>\n"
            "Also visit <a href=\"http://paypal.com\">http://paypal-verification.xyz</a>\n"
            "</body></html>\n"
            "--boundary-string\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "Content-Disposition: attachment; filename=\"alert.exe\"\n\n"
            "Mock attachment binary content\n"
            "--boundary-string--"
        )
        
        parsed = EmailParser.parse_raw_email(raw_email)
        
        self.assertEqual(parsed['subject'], "Urgent security update required")
        self.assertEqual(parsed['from'], "Alice <alice@safe-company.com>")
        self.assertEqual(parsed['to'], "Bob <bob@example.com>")
        
        # Verify links extracted
        self.assertEqual(len(parsed['links']), 2)
        urls = [l['url'] for l in parsed['links']]
        self.assertIn("https://malicious-domain.xyz/verify", urls)
        self.assertIn("http://paypal.com", urls)
        
        # Verify anchor texts
        anchors = {l['url']: l['anchor_text'] for l in parsed['links']}
        self.assertEqual(anchors["https://malicious-domain.xyz/verify"], "Confirm account")
        self.assertEqual(anchors["http://paypal.com"], "http://paypal-verification.xyz")
        
        # Verify attachments extracted
        self.assertEqual(len(parsed['attachments']), 1)
        att = parsed['attachments'][0]
        self.assertEqual(att['filename'], "alert.exe")
        self.assertEqual(att['size'], 30)
        self.assertIsNotNone(att['sha256'])

    def test_heuristics(self):
        # Test mismatched domain and urgency keywords
        email_data = {
            'subject': "URGENT Action Required: Bank account alert",
            'from': "Support <support@bank.com>",
            'body_text': "Click this link immediately to verify: http://bank-update.xyz/login",
            'links': [
                {'url': "http://bank-update.xyz/login", 'anchor_text': "Update Bank Account", 'source': 'text'},
                {'url': "https://safe-domain.com", 'anchor_text': "https://another-safe-domain.com", 'source': 'html'} # Display mismatch
            ]
        }
        
        result = HeuristicsAnalyzer.analyze(email_data)
        
        self.assertTrue(result['flags']['domain_mismatch'])
        self.assertTrue(result['flags']['urgency_detected'])
        self.assertTrue(result['flags']['display_text_mismatch'])
        self.assertTrue(result['flags']['suspicious_tld']) # .xyz is suspicious
        
        # Ensure we have reasons listed
        self.assertGreater(len(result['reasons']), 0)
        self.assertTrue(any("urgency" in r.lower() for r in result['reasons']))
        self.assertTrue(any("mismatch" in r.lower() for r in result['reasons']))

    def test_domain_verification(self):
        email_data = {
            'subject': "Security update",
            'from': "Support <support@paypa1.com>",
            'body_text': "Please visit http://thisdomainiscompletelyfake12345.xyz",
            'links': [
                {'url': "http://thisdomainiscompletelyfake12345.xyz", 'anchor_text': "Click here", 'source': 'text'}
            ]
        }
        result = HeuristicsAnalyzer.analyze(email_data)
        self.assertTrue(result['flags']['fake_domain_detected'])
        reasons_str = " ".join(result['reasons']).lower()
        self.assertTrue("impersonate" in reasons_str or "likely a fake domain" in reasons_str)

    def test_naive_bayes_classifier(self):
        classifier = NaiveBayesClassifier()
        
        emails = [
            "Meeting agenda for Wednesday morning planning sync",
            "Urgent password reset required immediately click link now",
            "Hey, let's grab coffee today at lunch",
            "Security alert: unauthorized login detected verify account"
        ]
        labels = ["Safe", "Malicious", "Safe", "Malicious"]
        
        classifier.train(emails, labels)
        
        # Save and reload
        classifier.save(self.model_path)
        
        new_classifier = NaiveBayesClassifier()
        self.assertTrue(new_classifier.load(self.model_path))
        
        # Check prediction on new safe-sounding email
        pred, conf, score = new_classifier.predict("Let's meet on Wednesday morning to discuss")
        self.assertEqual(pred, "Safe")
        
        # Check prediction on phishing-sounding email
        pred, conf, score = new_classifier.predict("Urgent security alert: reset password immediately")
        self.assertEqual(pred, "Malicious")

    def test_email_analyzer_integration(self):
        # Write dummy model state to test dir
        analyzer = EmailAnalyzer(model_dir=self.test_dir)
        
        raw_email = (
            "From: Billing <billing@secure-net.com>\n"
            "Subject: URGENT: Action Required on your account\n\n"
            "Verify your credit card status here: http://billing-update.top/card"
        )
        
        result = analyzer.analyze_email(raw_email)
        
        # Verify aggregate assessment is POTENTIAL PHISHING due to top TLD and urgency
        self.assertEqual(result['assessment'], "POTENTIAL PHISHING")
        self.assertTrue(result['heuristics']['flags']['urgency_detected'])
        self.assertTrue(result['heuristics']['flags']['suspicious_tld'])
        
        # Test feedback logging
        logged = analyzer.log_feedback(
            email_metadata=result['metadata'],
            prediction=result['ml']['prediction'],
            confidence=result['ml']['confidence'],
            human_verdict="Malicious"
        )
        self.assertTrue(logged)
        self.assertTrue(os.path.exists(analyzer.feedback_csv_path))
        
        # Retrain should work and save new model
        retrained = analyzer.retrain_model()
        self.assertTrue(retrained)


if __name__ == '__main__':
    unittest.main()

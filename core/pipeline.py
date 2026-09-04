from core.analyzer import analyze_text, calculate_risk
from core.security_classifier import SecurityClassifier
from core.history import save_analysis


class RazorGuardPipeline:

    def __init__(self):
        self.classifier = SecurityClassifier()

    def analyze(self, text):

        # =====================================================
        # Layer 1: Rule / Pattern Analysis
        # =====================================================

        findings = analyze_text(text)

        pattern_score, pattern_level = calculate_risk(findings)

        # =====================================================
        # Layer 2: AI Security Classification
        # =====================================================

        classifier_result = self.classifier.predict(text)

        label = classifier_result["label"]
        confidence = classifier_result["confidence"]

        classifier_scores = {
            "SAFE": 0,
            "SUSPICIOUS": 50,
            "MALICIOUS": 100,
        }

        raw_classifier_score = classifier_scores.get(label, 0)

        # Ignore uncertain AI predictions.
        if confidence < 0.70:
            classifier_score = 0
        else:
            classifier_score = round(
                raw_classifier_score * confidence
            )

        # =====================================================
        # Layer 3: Confidence-Aware Score Fusion
        # =====================================================

        RULE_WEIGHT = 0.70
        AI_WEIGHT = 0.30

        final_score = round(
            (pattern_score * RULE_WEIGHT)
            + (classifier_score * AI_WEIGHT)
        )

        final_score = min(final_score, 100)

        # =====================================================
        # Security Categories
        # =====================================================

        categories = {
            finding.get("category")
            for finding in findings
        }

        # =====================================================
        # Critical Security Categories
        # =====================================================

        critical_categories = {
            "secret_access",
            "security_bypass",
            "malware_execution",
            "malware",
            "unauthorized_access",
        }

        has_critical_finding = bool(
            categories.intersection(critical_categories)
        )

        # =====================================================
        # High-Risk Behavioral Categories
        # =====================================================

        high_risk_categories = {
            "credential_request",
            "credential_harvesting",
            "phishing",
            "data_exfiltration",
            "persistence",
            "social_engineering",
        }

        has_high_risk_behavior = bool(
            categories.intersection(high_risk_categories)
        )

        # =====================================================
        # Security Overrides
        # =====================================================

        # -----------------------------------------------------
        # Critical findings
        # -----------------------------------------------------
        #
        # A genuinely critical category must remain CRITICAL.
        #
        if has_critical_finding:
            final_score = max(final_score, 80)

        # -----------------------------------------------------
        # High-risk behavioral findings
        # -----------------------------------------------------
        #
        # These must remain HIGH, but should not become CRITICAL
        # solely because the AI classifier produced a high score.
        #
        elif has_high_risk_behavior:
            final_score = max(final_score, 50)
            final_score = min(final_score, 79)

        # -----------------------------------------------------
        # Multiple suspicious findings
        # -----------------------------------------------------

        if len(findings) >= 2:
            final_score = max(final_score, 50)

        final_score = min(final_score, 100)

        # =====================================================
        # Final Risk Level
        # =====================================================

        if final_score >= 80:
            final_level = "CRITICAL"

        elif final_score >= 50:
            final_level = "HIGH"

        elif final_score >= 25:
            final_level = "MEDIUM"

        elif final_score > 0:
            final_level = "LOW"

        else:
            final_level = "SAFE"

        # =====================================================
        # Final Result
        # =====================================================

        result = {
            "text": text,
            "risk_score": final_score,
            "risk_level": final_level,
            "findings": findings,
            "classifier": classifier_result,
            "pattern_score": pattern_score,
            "classifier_score": classifier_score,
        }

        # =====================================================
        # Persistent Analysis History
        # =====================================================

        save_analysis(text, result)

        return result
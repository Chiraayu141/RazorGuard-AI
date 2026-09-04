from core.patterns import detect_patterns


# =============================================================
# Severity Scores
# =============================================================

SEVERITY_SCORES = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 40,
    "CRITICAL": 60,
}


# =============================================================
# Category Severity Mapping
# =============================================================

CATEGORY_SEVERITIES = {
    "credential_request": "HIGH",
    "secret_access": "CRITICAL",
    "security_bypass": "CRITICAL",
    "suspicious_instruction": "MEDIUM",
    "phishing": "HIGH",
    "malware_execution": "CRITICAL",
    "data_exfiltration": "CRITICAL",
    "unauthorized_access": "CRITICAL",
    "persistence": "HIGH",
    "social_engineering": "MEDIUM",
}


# =============================================================
# Category Risk Bonuses
# =============================================================

CATEGORY_BONUSES = {
    "security_bypass": 10,
    "credential_request": 10,
    "secret_access": 10,
    "credential_harvesting": 10,
    "malware": 10,
    "malware_execution": 10,
    "phishing": 5,
    "data_exfiltration": 20,
    "unauthorized_access": 15,
    "persistence": 10,
    "social_engineering": 5,
    "suspicious_instruction": 5,
}


# =============================================================
# Benign Password Contexts
# =============================================================

BENIGN_PASSWORD_CONTEXTS = [
    "update my password",
    "updated my password",
    "updating my password",
    "change my password",
    "changed my password",
    "changing my password",
    "reset my password",
    "resetting my password",
    "forgot my password",
    "forgotten my password",
    "new password",
    "create a new password",
    "set a new password",
    "password reset",
]


# =============================================================
# Educational / Awareness Contexts
# =============================================================

EDUCATIONAL_CONTEXTS = [
    "in cybersecurity class",
    "in cyber security class",
    "in cybersecurity",
    "in cyber security",
    "cybersecurity class",
    "cyber security class",
    "we learned about",
    "we learn about",
    "learned about",
    "learning about",
    "study of",
    "studying",
    "for educational purposes",
    "educational example",
    "security awareness",
    "security training",
    "cybersecurity training",
    "cyber security training",
]


# =============================================================
# Keyword Rules
# =============================================================

KEYWORD_RULES = {
    "password": {
        "severity": "HIGH",
        "category": "credential_request",
    },
    "api key": {
        "severity": "CRITICAL",
        "category": "secret_access",
    },
    "secret": {
        "severity": "HIGH",
        "category": "secret_access",
    },
    "token": {
        "severity": "HIGH",
        "category": "secret_access",
    },
    "malware": {
        "severity": "CRITICAL",
        "category": "malware_execution",
    },
    "phishing": {
        "severity": "HIGH",
        "category": "phishing",
    },
}


# =============================================================
# Text Analysis
# =============================================================

def analyze_text(text):
    """
    Analyze text using suspicious patterns and keyword rules.

    The analyzer detects actual suspicious instructions and
    security-related keywords while reducing obvious false
    positives in educational/security-awareness contexts.
    """

    findings = []

    if not text or not text.strip():
        return findings

    text_lower = text.lower().strip()

    # ---------------------------------------------------------
    # Detect suspicious multi-word patterns
    # ---------------------------------------------------------

    pattern_matches = detect_patterns(text)

    for match in pattern_matches:
        category = match.get("category", "unknown").lower()

        severity = CATEGORY_SEVERITIES.get(
            category,
            "HIGH",
        )

        contribution = SEVERITY_SCORES[severity]

        contribution += CATEGORY_BONUSES.get(
            category,
            0,
        )

        findings.append({
            "type": "pattern",
            "keyword": match["pattern"],
            "category": match["category"],
            "severity": severity,
            "score_contribution": contribution,
        })

    # ---------------------------------------------------------
    # Detect keyword-based indicators
    # ---------------------------------------------------------

    for keyword, rule in KEYWORD_RULES.items():

        if keyword not in text_lower:
            continue

        # -----------------------------------------------------
        # Password false-positive protection
        # -----------------------------------------------------

        if (
            keyword == "password"
            and any(
                context in text_lower
                for context in BENIGN_PASSWORD_CONTEXTS
            )
        ):
            continue

        # -----------------------------------------------------
        # Educational-context protection
        #
        # Example:
        # "In cybersecurity class, we learned about phishing."
        #
        # Security terms in an educational sentence should not
        # automatically be treated as an active threat.
        # -----------------------------------------------------

        if any(
            context in text_lower
            for context in EDUCATIONAL_CONTEXTS
        ):
            continue

        severity = rule["severity"]
        category = rule["category"]

        findings.append({
            "type": "keyword",
            "keyword": keyword,
            "severity": severity,
            "category": category,
            "score_contribution": SEVERITY_SCORES[severity],
        })

    return findings


# =============================================================
# Risk Calculation
# =============================================================

def calculate_risk(findings):
    """
    Calculate the final rule-based risk score and risk level.
    """

    if not findings:
        return 0, "SAFE"

    score = 0

    for finding in findings:

        contribution = finding.get(
            "score_contribution",
            SEVERITY_SCORES[finding["severity"]],
        )

        score += contribution

    # Never allow the rule-based score to exceed 100.
    score = min(score, 100)

    # ---------------------------------------------------------
    # Risk Level
    # ---------------------------------------------------------

    if any(
        finding["severity"] == "CRITICAL"
        for finding in findings
    ):
        level = "CRITICAL"

    elif score >= 50:
        level = "HIGH"

    elif score >= 25:
        level = "MEDIUM"

    elif score > 0:
        level = "LOW"

    else:
        level = "SAFE"

    return score, level
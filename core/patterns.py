SUSPICIOUS_PATTERNS = {

    # =========================================================
    # Credential Harvesting
    # =========================================================

    "credential_request": [
        "send me your credentials",
        "send your credentials",
        "share your credentials",
        "give me your password",
        "tell me your password",
        "provide your password",
        "send me your password",
        "share your password",
        "provide me your password",
        "login credentials",
        "send me your login",
        "send your login details",
        "share your login details",
        "give me your login details",
        "provide your login details",
        "enter your password here",
        "enter your credentials here",
        "send me your username and password",
        "send your username and password",
        "give me your username and password",
    ],

    # =========================================================
    # API Keys / Secrets
    # =========================================================

    "secret_access": [
        "send me your api key",
        "share your api key",
        "give me your api key",
        "provide your api key",
        "send the api key",
        "share the api key",
        "send me the token",
        "share the token",
        "give me the token",
        "provide the token",
        "send me the secret",
        "share the secret key",
        "give me the secret key",
        "provide the secret key",

        # Additional secret-access patterns
        "reveal the secret",
        "reveal the secret key",
        "show me the secret",
        "show me the secret key",
        "retrieve the secret key",
        "extract the secret key",
        "access the secret key",
        "get the secret key",
        "read the secret key",
    ],

    # =========================================================
    # Security Bypass
    # =========================================================

    "security_bypass": [
        "bypass security",
        "disable security",
        "disable antivirus",
        "turn off antivirus",
        "ignore security",
        "disable firewall",
        "turn off firewall",
        "bypass antivirus",
        "disable endpoint protection",
        "turn off endpoint protection",
        "disable security software",
        "turn off security software",
        "disable protection",
        "turn off protection",
        "bypass detection",
        "bypass security controls",
        "disable monitoring",
        "turn off monitoring",
        "disable logging",
        "turn off logging",
    ],

    # =========================================================
    # Suspicious Instructions
    # =========================================================

    "suspicious_instruction": [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore the previous instructions",
        "do not tell anyone",
        "don't tell anyone",
        "keep this secret",
        "keep this confidential",
        "do not report this",
        "don't report this",
        "hide this from",
        "do not inform",
        "don't inform",
        "delete the evidence",
        "delete the logs",
        "remove the logs",
    ],

    # =========================================================
    # Phishing
    # =========================================================

    "phishing": [
        "verify your account immediately",
        "verify your account now",
        "verify your account",
        "confirm your account immediately",
        "confirm your account now",
        "confirm your identity immediately",
        "confirm your identity now",
        "click this link to verify",
        "click the link to verify",
        "click here to verify",
        "your account will be suspended",
        "your account has been suspended",
        "your account is suspended",
        "login to verify your account",
        "log in to verify your account",
        "verify your identity",
        "confirm your identity",
        "urgent account verification",
        "security alert verify your account",
        "unusual activity on your account",
        "suspicious activity on your account",
    ],

    # =========================================================
    # Malware Execution
    # =========================================================

    "malware_execution": [
        "run this malware",
        "execute this malware",
        "run the malicious file",
        "execute the malicious file",
        "open this infected file",
        "run this suspicious file",
        "execute this suspicious file",
        "launch the malware",
        "launch the malicious file",
        "install the malware",
        "install this malicious file",
        "run the payload",
        "execute the payload",
        "execute the payload immediately",
    ],

    # =========================================================
    # Data Exfiltration
    # =========================================================

    "data_exfiltration": [
        "send the confidential files",
        "send confidential files",
        "upload the confidential files",
        "upload confidential data",
        "send sensitive data",
        "send the sensitive data",
        "copy the database",
        "export the database",
        "upload the database",
        "send the database",
        "download the customer database",
        "copy customer records",
        "export customer records",
        "send customer records",
        "upload customer records",
        "send internal files",
        "upload internal files",
    ],

    # =========================================================
    # Unauthorized Access
    # =========================================================

    "unauthorized_access": [
        "access someone else's account",
        "access another user's account",
        "access another account",
        "log into someone else's account",
        "log in to someone else's account",
        "use someone else's credentials",
        "use another user's credentials",
        "steal the credentials",
        "steal their password",
        "steal the password",
        "take over the account",
        "take control of the account",

        # Additional unauthorized-access patterns
        "access the admin account without permission",
        "access the administrator account without permission",
        "access an admin account without permission",
        "access the account without permission",
        "access the system without permission",
        "access the server without permission",
        "log into the admin account without permission",
        "log in to the admin account without permission",
        "gain unauthorized access",
        "gain access without permission",
        "access without authorization",
    ],

    # =========================================================
    # Persistence / Privilege Abuse
    # =========================================================

    "persistence": [
        "create a hidden account",
        "create a backdoor",
        "install a backdoor",
        "maintain access",
        "keep persistent access",
        "establish persistence",
        "maintain persistence",
        "hide the process",
        "hide the service",

        # Additional persistence patterns
        "create a startup entry",
        "create a startup entry so",
        "run automatically at startup",
        "run automatically on startup",
        "start automatically at startup",
        "launch automatically at startup",
        "add a startup entry",
        "add a startup program",
        "create an autorun entry",
        "create an autorun",
        "make the program start automatically",
    ],

    # =========================================================
    # Urgency / Social Engineering
    # =========================================================

    "social_engineering": [
        "act immediately",
        "do this immediately",
        "do this now",
        "urgent action required",
        "immediate action required",
        "respond immediately",
        "respond now",
        "your account is at risk",
        "your account is in danger",
        "failure to comply",
        "failure to respond",
        "final warning",
        "last warning",

        # Additional social-engineering patterns
        "pretend to be the administrator",
        "pretend to be an administrator",
        "pretend to be the admin",
        "impersonate the administrator",
        "impersonate the admin",
        "convince the user to help",
        "convince the user",
        "trick the user",
        "deceive the user",
    ],
}


def detect_patterns(text):
    """Detect suspicious multi-word security patterns."""

    text_lower = text.lower()

    matches = []

    for category, patterns in SUSPICIOUS_PATTERNS.items():

        for pattern in patterns:

            if pattern in text_lower:

                matches.append({
                    "category": category,
                    "pattern": pattern,
                })

    return matches
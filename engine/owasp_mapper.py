"""
OWASPMapper — Enriches findings with canonical OWASP Top 10 (2021) classification.
"""
from typing import Tuple, Optional


class OWASPMapper:
    CATEGORIES = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable and Outdated Components",
        "A07:2021": "Identification and Authentication Failures",
        "A08:2021": "Software and Data Integrity Failures",
        "A09:2021": "Security Logging and Monitoring Failures",
        "A10:2021": "Server-Side Request Forgery (SSRF)",
    }

    KEYWORD_MAPPINGS = [
        (["idor", "traversal", "access_control", "unauthorized", "privilege"], "A01:2021"),
        (["crypto", "hash", "md5", "sha1", "des", "cipher", "secret", "private_key", "password"], "A02:2021"),
        (["sql", "sqli", "xss", "inject", "rce", "eval", "command_injection"], "A03:2021"),
        (["prng", "math.random", "random", "insecure_design"], "A04:2021"),
        (["cors", "debug", "misconfig", "verbose", "default_credential"], "A05:2021"),
        (["dependency", "outdated", "cve", "package", "component"], "A06:2021"),
        (["jwt", "auth", "session", "token", "login"], "A07:2021"),
        (["deserializ", "integrity", "unsigned", "tamper"], "A08:2021"),
        (["log", "logging", "console.log", "audit"], "A09:2021"),
        (["ssrf", "request_forgery", "internal_url", "metadata"], "A10:2021"),
    ]

    @classmethod
    def resolve(
        cls,
        rule_id: str,
        category: Optional[str] = None,
        suggested_owasp_id: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Resolves the canonical OWASP ID and Name.
        Returns (owasp_id, owasp_name).
        """
        # If explicitly valid OWASP ID supplied
        if suggested_owasp_id and suggested_owasp_id in cls.CATEGORIES:
            return suggested_owasp_id, cls.CATEGORIES[suggested_owasp_id]

        # Match from Rule ID pattern, e.g. RULE_A03_SQL_CONCAT
        upper_rule = (rule_id or "").upper()
        for owasp_id in cls.CATEGORIES:
            compact = owasp_id.replace(":", "_").upper()  # A03_2021
            short = owasp_id.split(":")[0].upper()        # A03
            if short in upper_rule or compact in upper_rule:
                return owasp_id, cls.CATEGORIES[owasp_id]

        # Match against keywords in rule_id and category
        search_blob = f"{rule_id} {category or ''}".lower()
        for keywords, owasp_id in cls.KEYWORD_MAPPINGS:
            for kw in keywords:
                if kw in search_blob:
                    return owasp_id, cls.CATEGORIES[owasp_id]

        return None, None

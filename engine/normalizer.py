"""
FindingNormalizer — Converts scanner-native RawFinding into canonical Finding models.
Enforces deterministic SHA-256 fingerprint generation.
"""
import hashlib
import os
from typing import Optional, List
from engine.models import RawFinding, Finding
from engine.owasp_mapper import OWASPMapper
from engine.severity_engine import SeverityEngine


class FindingNormalizer:
    @staticmethod
    def compute_fingerprint(
        rule_id: str,
        file_path: Optional[str],
        line_start: Optional[int],
        evidence: Optional[str],
    ) -> str:
        """
        Computes a stable, deterministic SHA-256 hash invariant across scans.
        Normalizes paths (forward slashes, stripped roots) and whitespace.
        """
        norm_path = ""
        if file_path:
            norm_path = file_path.replace("\\", "/").strip().lstrip("./")

        norm_line = str(line_start or 0)
        norm_evidence = (evidence or "").strip()[:300]
        norm_rule = (rule_id or "UNKNOWN").strip().upper()

        seed = f"{norm_rule}:{norm_path}:{norm_line}:{norm_evidence}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    @classmethod
    def normalize(cls, raw: RawFinding) -> Finding:
        """Transforms a RawFinding into an immutable canonical Finding."""
        # Normalize severity
        normalized_sev = SeverityEngine.normalize(raw.severity)
        normalized_conf = raw.confidence.upper() if raw.confidence else "HIGH"
        if normalized_conf not in ("HIGH", "MEDIUM", "LOW"):
            normalized_conf = "HIGH"

        # Resolve OWASP mapping
        owasp_id, owasp_name = OWASPMapper.resolve(raw.rule_id, raw.category, raw.owasp_id)

        # Standardize category
        category = raw.category or owasp_name or "General Security"

        # Sanitize evidence snippet
        evidence = raw.evidence.strip()[:500] if raw.evidence else None

        # Clean file path
        clean_path = raw.file_path.replace("\\", "/").strip().lstrip("./") if raw.file_path else None

        # Compute stable fingerprint
        fingerprint = cls.compute_fingerprint(
            rule_id=raw.rule_id,
            file_path=clean_path,
            line_start=raw.line_start,
            evidence=evidence,
        )

        return Finding(
            rule_id=raw.rule_id,
            scanner=raw.scanner,
            title=raw.title,
            category=category,
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            severity=normalized_sev,
            confidence=normalized_conf,
            file_path=clean_path,
            line_start=raw.line_start,
            line_end=raw.line_end or raw.line_start,
            evidence=evidence,
            description=raw.description,
            impact=raw.impact,
            remediation=raw.remediation,
            status="OPEN",
            fingerprint=fingerprint,
        )

    @classmethod
    def normalize_batch(cls, raw_findings: List[RawFinding]) -> List[Finding]:
        """Normalizes a list of raw findings, deduplicating identical fingerprints."""
        seen_fingerprints = set()
        normalized_list = []

        for raw in raw_findings:
            finding = cls.normalize(raw)
            if finding.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(finding.fingerprint)
                normalized_list.append(finding)

        return normalized_list

"""
VerificationEngine — Re-scan comparison and lifecycle transition engine.
Tracks findings across scans using stable fingerprints:
OPEN, RESOLVED, REOPENED.
"""
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timezone
from engine.models import Finding


class VerificationEngine:
    @classmethod
    def diff_scans(
        cls,
        prior_findings: List[Finding],
        current_findings: List[Finding],
    ) -> Tuple[List[Finding], List[Dict[str, str]], bool]:
        """
        Compares prior scan findings against current scan findings.
        Returns:
            - reconciled_findings: List of findings with updated statuses
            - transition_log: List of status changes for audit history
            - has_new_findings: True if any finding was introduced for the first time
        """
        prior_map: Dict[str, Finding] = {f.fingerprint: f for f in prior_findings}
        current_fingerprints = {f.fingerprint for f in current_findings}

        reconciled: List[Finding] = []
        transitions: List[Dict[str, str]] = []
        has_new_findings = False
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Process all current findings
        for cur in current_findings:
            fp = cur.fingerprint
            if fp not in prior_map:
                # Brand new finding
                cur.status = "OPEN"
                cur.detected_at = cur.detected_at or now_iso
                reconciled.append(cur)
                transitions.append({
                    "fingerprint": fp,
                    "from_status": None,
                    "to_status": "OPEN",
                    "reason": "Initial detection in scan",
                })
                has_new_findings = True
            else:
                prior = prior_map[fp]
                if prior.status == "RESOLVED":
                    # Reintroduced vulnerability!
                    cur.status = "REOPENED"
                    cur.detected_at = prior.detected_at
                    cur.resolved_at = None
                    reconciled.append(cur)
                    transitions.append({
                        "fingerprint": fp,
                        "from_status": "RESOLVED",
                        "to_status": "REOPENED",
                        "reason": "Vulnerability reappeared in new commit",
                    })
                    has_new_findings = True
                else:
                    # Still open
                    cur.status = prior.status
                    cur.detected_at = prior.detected_at
                    reconciled.append(cur)

        # 2. Check previously OPEN or REOPENED findings that are now absent (fixed!)
        for prior_fp, prior in prior_map.items():
            if prior_fp not in current_fingerprints and prior.status in ("OPEN", "REOPENED"):
                # Mark as RESOLVED
                resolved_finding = prior.model_copy(deep=True)
                resolved_finding.status = "RESOLVED"
                resolved_finding.resolved_at = now_iso
                reconciled.append(resolved_finding)
                transitions.append({
                    "fingerprint": prior_fp,
                    "from_status": prior.status,
                    "to_status": "RESOLVED",
                    "reason": "Vulnerability remediated and absent from scan",
                })

        return reconciled, transitions, has_new_findings

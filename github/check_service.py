"""
GitHubCheckService — Manages GitHub Check Runs and file annotations for Audit Bench.
Acts as the automated merge gate in developer Pull Requests.
"""
from typing import List, Dict, Any, Optional
import httpx
from engine.models import Finding


class GitHubCheckService:
    CHECK_NAME = "AUDIT BENCH SECURITY GATE"

    @classmethod
    def format_annotations(cls, findings: List[Finding], max_count: int = 50) -> List[Dict[str, Any]]:
        """Formats normalized findings into GitHub Check Run file annotations."""
        annotations = []
        for f in findings:
            if not f.file_path or f.status == "RESOLVED":
                continue

            level = "failure" if f.severity in ("CRITICAL", "HIGH") else "warning"
            line = f.line_start or 1
            annotations.append({
                "path": f.file_path,
                "start_line": line,
                "end_line": f.line_end or line,
                "annotation_level": level,
                "title": f"[{f.severity}] {f.title[:60]}",
                "message": f"{f.description or f.title}\n\nSuggested Fix:\n{f.remediation or 'Review code pattern.'}",
                "raw_details": f"OWASP: {f.owasp_id or 'N/A'} | Fingerprint: {f.fingerprint[:12]}",
            })

            if len(annotations) >= max_count:
                break

        return annotations

    @classmethod
    def generate_check_output(
        cls,
        score: int,
        policy_result: str,
        violations: List[str],
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """Builds structured summary markdown for GitHub Check Runs."""
        active = [f for f in findings if f.status in ("OPEN", "REOPENED")]
        crit = sum(1 for f in active if f.severity == "CRITICAL")
        high = sum(1 for f in active if f.severity == "HIGH")
        med = sum(1 for f in active if f.severity == "MEDIUM")
        low = sum(1 for f in active if f.severity == "LOW")

        conclusion = "success" if policy_result == "PASS" else "failure"
        badge = "[PASSED]" if conclusion == "success" else "[FAILED]"

        title = f"Security Score: {score}/100 — {badge}"

        summary_lines = [
            f"### Audit Bench Security Gate Decision: **{policy_result}**",
            f"**Final Security Score:** `{score}/100`",
            "",
            "| Severity | Active Findings |",
            "|---|---|",
            f"| Critical | **{crit}** |",
            f"| High | **{high}** |",
            f"| Medium | **{med}** |",
            f"| Low | **{low}** |",
            f"| **Total** | **{len(active)}** |",
            "",
        ]

        if violations:
            summary_lines.append("#### [FAILED] Policy Violations:")
            for v in violations:
                summary_lines.append(f"- {v}")
            summary_lines.append("")
        else:
            summary_lines.append("#### [PASSED] All Security Policies Satisfied.")
            summary_lines.append("Code changes comply with organizational security baselines.")

        annotations = cls.format_annotations(findings)

        return {
            "title": title,
            "summary": "\n".join(summary_lines),
            "text": "Detailed findings and remediation instructions are available in the Audit Bench dashboard.",
            "annotations": annotations,
            "conclusion": conclusion,
        }

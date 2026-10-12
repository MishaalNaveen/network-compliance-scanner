"""Fixed rule-based policy priority, not a standardized vulnerability or risk score."""

RISK_ORDER = {"Low": 1, "Medium": 2, "High": 3}
POLICY_PRIORITY_LABELS = {
    "Low": "Routine verification under the configured service rule.",
    "Medium": "Normal policy review priority under the configured service rule.",
    "High": "Elevated review priority under the configured service rule.",
}


def classify_risk(status: str, baseline: str) -> tuple[str, str]:
    """Return the configured review priority and its meaning; no likelihood-impact formula is used."""
    if status == "violation":
        return "High", "Policy baseline violation: prioritized High by rule; this is not a CVSS score."
    if status == "review":
        if baseline not in RISK_ORDER:
            raise ValueError(f"Unsupported policy priority: {baseline}")
        return baseline, f"Review priority set to {baseline} by service rule; not a CVSS or NIST risk score."
    if status == "informational":
        if baseline not in RISK_ORDER:
            raise ValueError(f"Unsupported policy priority: {baseline}")
        return baseline, f"Informational policy priority set to {baseline}; not a CVSS or NIST risk score."
    raise ValueError(f"Unsupported compliance status: {status}")

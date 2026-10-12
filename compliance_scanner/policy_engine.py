"""Turn open-port observations into reviewable policy findings, not vulnerability claims."""
from .policy_definitions import FRAMEWORKS, POLICIES, UNEXPECTED_POLICY
from .risk_engine import classify_risk


def _select_policy(service, port, policies):
    for policy in policies.values():
        names = {policy.service.lower(), *(name.lower() for name in policy.service_names)}
        if service in names or port in policy.ports:
            return policy
    return UNEXPECTED_POLICY


def evaluate_services(services, policies=None):
    """Evaluate Nmap observations; any provided non-open states are ignored."""
    policies = policies or POLICIES
    findings = []
    for observed in services:
        state = str(observed.get("state", "open")).lower()
        if state != "open":
            continue
        port = int(observed["port"])
        protocol = str(observed.get("protocol") or "tcp").lower()
        raw_service = str(observed.get("service") or "unknown").strip()
        service_key = raw_service.lower()
        policy = _select_policy(service_key, port, policies)
        if policy is UNEXPECTED_POLICY:
            service = raw_service.title() if service_key != "unknown" else "Unexpected service"
        else:
            service = policy.service

        status = policy.status
        if status == "violation" and not policy.baseline_requirement:
            # A violation requires an explicit requirement to compare against.
            status = "review"
        risk, risk_reason = classify_risk(status, policy.risk)
        observed_text = (f"Nmap reported {protocol.upper()} port {port} open; service label: "
                         f"{raw_service or 'unknown'}. Nmap service labels may be inferred from the port "
                         "unless version detection identifies the service.")
        mappings = []
        for framework_id, rationale, limitation in policy.framework_rationales:
            mapping = dict(FRAMEWORKS[framework_id])
            mapping.update(rationale=rationale, evidence_limit=limitation)
            mappings.append(mapping)
        finding = {
            "port": port,
            "protocol": protocol,
            "service": service,
            "state": state,
            "observation": observed_text,
            "status": status,
            "policy_status": status,
            "violation_requirement": policy.baseline_requirement if status == "violation" else None,
            "risk": risk,
            "policy_priority": risk,
            "risk_reason": risk_reason,
            "explanation": policy.why_matters,
            "why_matters": policy.why_matters,
            "verification": policy.verification,
            "recommendation": policy.recommendation,
            "framework_mappings": mappings,
            # No vulnerability scanner or trusted CVE source is connected.
            "vulnerability_status": "not_assessed",
            "cve": None,
            "cvss_version": None,
            "cvss_score": None,
            "cvss_vector": None,
            "cvss_source": None,
            # Retain this field for older consumers and schema compatibility.
            "nist_csf": [mapping["identifier"] for mapping in mappings],
        }
        findings.append(finding)
    return findings

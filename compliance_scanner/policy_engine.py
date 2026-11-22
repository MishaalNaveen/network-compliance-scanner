"""Turn open-port observations into reviewable policy findings, not vulnerability claims."""
from .policy_definitions import FRAMEWORKS, POLICIES, UNEXPECTED_POLICY
from .risk_engine import classify_risk


RELEVANCE_LIMIT = "Framework relevance does not establish compliance or noncompliance."


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
        method = observed.get("service_method")
        tunnel = observed.get("service_tunnel")
        probed = method == "probed" and service_key not in {"", "unknown"}
        observed_text = (f"Nmap reported {protocol.upper()} port {port} open from the scan vantage point. "
                         f"Service label: {raw_service or 'unknown'}.")
        if probed:
            observed_text += " Nmap assigned the label through service probing."
            if tunnel:
                observed_text += f" Nmap reported a service tunnel ({tunnel})."
        elif method == "table":
            observed_text += " Nmap inferred the label from its port table. The service identity is unverified."
        else:
            observed_text += " The service identity is unverified because no matching probe result was recorded."

        mappings = []
        review_policy = policy
        if probed:
            # Keep existing finding priorities while basing references on the probed name.
            reference_service = "ssl/http" if service_key == "http" and tunnel == "ssl" else service_key
            review_policy = _select_policy(reference_service, None, policies)
        if probed and not tunnel:
            evidence = observed_text + " Nmap reported no TLS tunnel."
            for framework_id, rationale, limitation in review_policy.framework_rationales:
                mappings.append(dict(FRAMEWORKS[framework_id], category="Evidence-supported relevance",
                                     rationale=rationale, evidence=evidence, verification=review_policy.verification,
                                     evidence_limit=f"{limitation} {RELEVANCE_LIMIT}"))

        for framework_id, rationale, verification in review_policy.potential_references:
            mappings.append(dict(FRAMEWORKS[framework_id], category="Potential control relevance",
                                 rationale=rationale, evidence=observed_text, verification=verification,
                                 evidence_limit="The scan observed reachability from one vantage point. "
                                                f"It did not test this control. {RELEVANCE_LIMIT}"))
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
            "nist_csf": [mapping["identifier"] for mapping in mappings
                         if mapping["framework"] == "NIST Cybersecurity Framework"],
        }
        findings.append(finding)
    return findings

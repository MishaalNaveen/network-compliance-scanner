"""Editable service policies and narrowly justified framework references."""
from dataclasses import dataclass


FRAMEWORKS = {
    "PR.DS-02": {
        "framework": "NIST Cybersecurity Framework",
        "version": "2.0",
        "identifier": "PR.DS-02",
        "title": "The confidentiality, integrity, and availability of data-in-transit are protected",
        "source": "https://www.nist.gov/system/files/documents/2024/03/25/The_NIST_CSF_2-0_Core_With_Withdrawn_CSF_1-1_Elements.pdf",
    },
}

for identifier, title in (
    ("ID.AM-02", "Inventories of software, services, and systems managed by the organization are maintained"),
    ("PR.PS-01", "Configuration management practices are established and applied"),
    ("PR.IR-01", "Networks and environments are protected from unauthorized logical access and usage"),
    ("PR.AA-03", "Users, services, and hardware are authenticated"),
):
    FRAMEWORKS[identifier] = {
        "framework": "NIST Cybersecurity Framework",
        "version": "2.0",
        "identifier": identifier,
        "title": title,
        "source": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
    }

for identifier, title, description in (
    ("4.8", "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
     "Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function."),
    ("6.5", "Require MFA for Administrative Access",
     "Require MFA for all administrative access accounts, where supported, on all enterprise assets, whether managed on-site or through a service provider."),
):
    FRAMEWORKS[identifier] = {
        "framework": "CIS Controls",
        "version": "8.1",
        "identifier": identifier,
        "title": title,
        "description": description,
        "source": "https://www.cisecurity.org/controls/cis-controls-navigator",
    }


@dataclass(frozen=True)
class Policy:
    service: str
    ports: tuple[int, ...]
    status: str
    risk: str
    why_matters: str
    verification: str
    recommendation: str
    service_names: tuple[str, ...] = ()
    framework_rationales: tuple[tuple[str, str, str], ...] = ()
    baseline_requirement: str | None = None
    # Tuples contain the reference ID, rationale, and next verification step.
    potential_references: tuple[tuple[str, str, str], ...] = ()

    @property
    def nist_csf(self):
        """Compatibility view for existing callers; IDs are defined in FRAMEWORKS."""
        references = self.framework_rationales + self.potential_references
        return tuple(identifier for identifier, _, _ in references
                     if FRAMEWORKS[identifier]["framework"] == "NIST Cybersecurity Framework")


# Mapping tuples are (framework identifier, why relevant, evidence limitation).
# The observation can justify further review; it never certifies an outcome.
_TRANSIT_MAPPING = ("PR.DS-02",
    "Nmap identified a service that can carry cleartext traffic by probing, with no TLS tunnel reported. Verify how data in transit is protected.",
    "The probe does not establish whether TLS is required or negotiated, whether sensitive data travels in cleartext, or whether a policy baseline was violated.")

_SERVICE_NECESSITY = ("4.8",
    "The reachable listener is a candidate for review of whether an enterprise service is still needed.",
    "Identify the listener and its owner, then check approved business need and dependencies before deciding whether to disable it.")

_ADMIN_MFA = ("6.5",
    "If the listener is used for enterprise administration, the authentication path may be in scope for administrative MFA.",
    "Confirm administrative use and MFA support, then check enforcement for administrative accounts across direct and gateway access paths.")

_SERVICE_INVENTORY = ("ID.AM-02",
    "A listener outside the scanner's known service rules gives the owner a specific endpoint to reconcile with the managed service inventory.",
    "Identify the listener process and owner, then reconcile them with the approved service inventory.")

POLICIES = {
    "telnet": Policy("Telnet", (23,), "review", "High",
        "Telnet is commonly an unencrypted remote-management protocol; an exposed listener can put credentials and session data at risk.",
        "Confirm the service identity, whether it is reachable beyond a trusted management network, and whether the organization permits cleartext management.",
        "Disable Telnet where it is not required; use SSH through an approved management path with strong authentication.",
        ("telnet",), (_TRANSIT_MAPPING,), potential_references=(_SERVICE_NECESSITY,)),
    "ftp": Policy("FTP", (21,), "review", "High",
        "The FTP service label may represent standard FTP, which can send credentials and file contents without encryption; explicit FTPS was not tested.",
        "Confirm whether this is standard FTP or FTPS, inspect server configuration and authentication, and check network reachability.",
        "Disable unused FTP. Where file transfer is needed, require an approved encrypted protocol such as SFTP or correctly configured FTPS.",
        ("ftp", "ftp-data"), (_TRANSIT_MAPPING,), potential_references=(_SERVICE_NECESSITY,)),
    "ssh": Policy("SSH", (22,), "review", "Medium",
        "SSH is a remote-administration service. Its exposure can increase the reachable management surface, but the scan does not test access policy or SSH configuration.",
        "Verify allowed source networks, account authorization, MFA or key policy, supported algorithms, patch level, and authentication logging.",
        "Restrict SSH to approved management paths, enforce the organization’s authentication baseline, and keep the server patched.",
        ("ssh",), potential_references=(
            ("PR.AA-03", "If this is SSH, the listener provides a path for remote authentication.",
             "Confirm SSH and review allowed authentication methods and enforcement at the host or management gateway."),
            _ADMIN_MFA,
        )),
    "http": Policy("HTTP", (80,), "review", "Medium",
        "Nmap reported an HTTP service or a port conventionally associated with HTTP. Plain HTTP does not protect application data in transit; redirects and application behavior were not tested.",
        "Confirm service identity and intended exposure; test HTTP-to-HTTPS redirection and ensure sensitive endpoints do not accept cleartext traffic.",
        "Use HTTPS for sensitive application traffic and redirect or disable unnecessary cleartext HTTP endpoints.",
        ("http", "http-proxy", "http-alt"), (_TRANSIT_MAPPING,), potential_references=(
            ("PR.PS-01", "The reachable endpoint is a concrete listener setting to reconcile with the platform's approved configuration.",
             "Identify the listener and compare its binding, enabled routes, and intended exposure with the approved configuration."),
        )),
    "https": Policy("HTTPS", (443,), "review", "Low",
        "Nmap reported an HTTPS service or port 443. Port reachability does not establish TLS versions, certificate validity, application security, or identity controls.",
        "Separately assess the certificate chain and expiry, TLS protocol/cipher configuration, hostname validation, and application security.",
        "Correct any certificate or TLS configuration findings and apply the organization’s web-application security baseline.",
        ("https", "ssl/http"), potential_references=(
            ("PR.DS-02", "If the listener serves HTTPS, its transport settings are relevant to protecting application data in transit.",
             "Confirm HTTPS and review TLS termination, versions, ciphers, certificate and hostname validation, and any unprotected forwarding paths."),
        )),
    "smb": Policy("SMB", (139, 445), "review", "High",
        "SMB/NetBIOS exposure may make file-sharing and remote-management interfaces reachable. An open port alone does not establish weak permissions or a vulnerable protocol.",
        "Verify network restrictions, SMB protocol versions and signing, guest access, share permissions, and whether the service is required.",
        "Restrict SMB to approved internal segments; disable obsolete protocols and guest access, and apply least-privilege share permissions.",
        ("smb", "microsoft-ds", "netbios-ssn", "netbios"), potential_references=(
            ("PR.IR-01", "If this listener provides SMB or NetBIOS, it may expose file-sharing or management interfaces to the scanning network.",
             "Identify the service and compare permitted client networks with host firewall and network segmentation rules."),
            _SERVICE_NECESSITY,
        )),
    "msrpc": Policy("MSRPC", (135, 593), "review", "Medium",
        "MSRPC endpoint mapping or RPC over HTTP is reachable. This may expose remote procedure interfaces; the scan does not enumerate methods, permissions, or vulnerabilities.",
        "Confirm which RPC services are required, inspect host firewall scope and endpoint exposure, and review service-specific access controls.",
        "Limit RPC reachability to required trusted hosts and disable unneeded RPC services using the system owner’s change process.",
        ("msrpc", "dce-rpc", "rpc", "ncacn_http"), potential_references=(
            ("PR.IR-01", "If this is an RPC endpoint, it may make remotely callable interfaces reachable from the scanning network.",
             "Identify enabled RPC interfaces and verify which client networks can reach the endpoint mapper and associated services."),
        )),
    "rdp": Policy("RDP", (3389,), "review", "High",
        "Remote Desktop is a sensitive remote-administration surface. Reachability does not prove that authentication is weak or that the host is vulnerable.",
        "Verify source-network restrictions, MFA, Network Level Authentication, account lockout policy, patching, and access monitoring.",
        "Restrict RDP to managed access paths, require the approved authentication baseline, and disable it when not needed.",
        ("ms-wbt-server", "rdp"), potential_references=(
            ("PR.AA-03", "If this is RDP, it is an authentication entry point for interactive remote sessions.",
             "Confirm RDP and review Network Level Authentication, gateway authentication, and direct access paths."),
            _ADMIN_MFA,
        )),
}

UNEXPECTED_POLICY = Policy("Unexpected service", (), "review", "Medium",
    "Nmap reported an open port whose business purpose or approved exposure has not been established.",
    "Identify the service owner, business purpose, listener process, and approved network scope.",
    "Confirm ownership and need; restrict or close the port through the normal change process if it is not approved.",
    potential_references=(_SERVICE_INVENTORY,))

"""Editable service policies and narrowly justified framework references."""
from dataclasses import dataclass


FRAMEWORKS = {
    "PR.DS-02": {
        "framework": "NIST Cybersecurity Framework",
        "version": "2.0",
        "identifier": "PR.DS-02",
        "title": "The confidentiality, integrity, and availability of data-in-transit are protected",
        "source": "https://www.nist.gov/system/files/documents/2024/03/25/The_NIST_CSF_2-0_Core_With_Withdrawn_CSF_1-1_Elements.pdf",
    }
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

    @property
    def nist_csf(self):
        """Compatibility view for existing callers; IDs are defined in FRAMEWORKS."""
        return tuple(ref[0] for ref in self.framework_rationales)


# Mapping tuples are (framework identifier, why relevant, evidence limitation).
# The observation can justify further review; it never certifies an outcome.
_TRANSIT_MAPPING = ("PR.DS-02",
    "The detected plaintext-capable service makes protection of data in transit relevant to verify.",
    "A port/service observation does not inspect application traffic or prove sensitive data was transmitted.")

POLICIES = {
    "telnet": Policy("Telnet", (23,), "review", "High",
        "Telnet is commonly an unencrypted remote-management protocol; an exposed listener can put credentials and session data at risk.",
        "Confirm the service identity, whether it is reachable beyond a trusted management network, and whether the organization permits cleartext management.",
        "Disable Telnet where it is not required; use SSH through an approved management path with strong authentication.",
        ("telnet",), (_TRANSIT_MAPPING,)),
    "ftp": Policy("FTP", (21,), "review", "High",
        "The FTP service label may represent standard FTP, which can send credentials and file contents without encryption; explicit FTPS was not tested.",
        "Confirm whether this is standard FTP or FTPS, inspect server configuration and authentication, and check network reachability.",
        "Disable unused FTP. Where file transfer is needed, require an approved encrypted protocol such as SFTP or correctly configured FTPS.",
        ("ftp", "ftp-data"), (_TRANSIT_MAPPING,)),
    "ssh": Policy("SSH", (22,), "review", "Medium",
        "SSH is a remote-administration service. Its exposure can increase the reachable management surface, but the scan does not test access policy or SSH configuration.",
        "Verify allowed source networks, account authorization, MFA or key policy, supported algorithms, patch level, and authentication logging.",
        "Restrict SSH to approved management paths, enforce the organization’s authentication baseline, and keep the server patched.",
        ("ssh",)),
    "http": Policy("HTTP", (80,), "review", "Medium",
        "Nmap reported an HTTP service or a port conventionally associated with HTTP. Plain HTTP does not protect application data in transit; redirects and application behavior were not tested.",
        "Confirm service identity and intended exposure; test HTTP-to-HTTPS redirection and ensure sensitive endpoints do not accept cleartext traffic.",
        "Use HTTPS for sensitive application traffic and redirect or disable unnecessary cleartext HTTP endpoints.",
        ("http", "http-proxy", "http-alt"), (_TRANSIT_MAPPING,)),
    "https": Policy("HTTPS", (443,), "review", "Low",
        "Nmap reported an HTTPS service or port 443. Port reachability does not establish TLS versions, certificate validity, application security, or identity controls.",
        "Separately assess the certificate chain and expiry, TLS protocol/cipher configuration, hostname validation, and application security.",
        "Correct any certificate or TLS configuration findings and apply the organization’s web-application security baseline.",
        ("https", "ssl/http")),
    "smb": Policy("SMB", (139, 445), "review", "High",
        "SMB/NetBIOS exposure may make file-sharing and remote-management interfaces reachable. An open port alone does not establish weak permissions or a vulnerable protocol.",
        "Verify network restrictions, SMB protocol versions and signing, guest access, share permissions, and whether the service is required.",
        "Restrict SMB to approved internal segments; disable obsolete protocols and guest access, and apply least-privilege share permissions.",
        ("smb", "microsoft-ds", "netbios-ssn", "netbios")),
    "msrpc": Policy("MSRPC", (135, 593), "review", "Medium",
        "MSRPC endpoint mapping or RPC over HTTP is reachable. This may expose remote procedure interfaces; the scan does not enumerate methods, permissions, or vulnerabilities.",
        "Confirm which RPC services are required, inspect host firewall scope and endpoint exposure, and review service-specific access controls.",
        "Limit RPC reachability to required trusted hosts and disable unneeded RPC services using the system owner’s change process.",
        ("msrpc", "dce-rpc", "rpc", "ncacn_http")),
    "rdp": Policy("RDP", (3389,), "review", "High",
        "Remote Desktop is a sensitive remote-administration surface. Reachability does not prove that authentication is weak or that the host is vulnerable.",
        "Verify source-network restrictions, MFA, Network Level Authentication, account lockout policy, patching, and access monitoring.",
        "Restrict RDP to managed access paths, require the approved authentication baseline, and disable it when not needed.",
        ("ms-wbt-server", "rdp")),
}

UNEXPECTED_POLICY = Policy("Unexpected service", (), "review", "Medium",
    "Nmap reported an open port whose business purpose or approved exposure has not been established.",
    "Identify the service owner, business purpose, listener process, and approved network scope.",
    "Confirm ownership and need; restrict or close the port through the normal change process if it is not approved.")

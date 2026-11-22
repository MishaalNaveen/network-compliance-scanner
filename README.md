# Network Security Compliance and Risk Assessment Scanner

A Flask and Nmap application that turns open service observations into policy findings, explainable policy priorities, and remediation guidance. Scans run only after an authorized user submits the form; Nmap is not invoked at application startup.

## Windows setup and run

Use the project-local environment:

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

Nmap is a separate Windows application. The default path is `C:\Program Files (x86)\Nmap\nmap.exe`. To override it for the current PowerShell session:

```powershell
$env:NMAP_PATH = 'C:\Program Files (x86)\Nmap\nmap.exe'
.venv\Scripts\python app.py
```

The `NMAP_PATH` variable overrides the default executable. The `Scanner` class also accepts an explicit `executable` argument; `create_app` accepts `NMAP_EXECUTABLE` in its configuration. Nmap is called using an argument list and `shell=False`. Scan flags are fixed by the profile and cannot be supplied in the form.

Open `http://127.0.0.1:5000`, enter one hostname or IP, choose a profile, confirm that you are authorized, and submit to start a scan. For your own machine, use `127.0.0.1` or `::1`. Scan another system only with explicit authorization; scans can trigger monitoring and firewall alerts. CIDR ranges are not accepted.

Run tests with:

```powershell
.venv\Scripts\python -m unittest discover -v
```

The test suite mocks Nmap subprocess calls and does not scan networks.

## Assessment profiles

- **Safe discovery**: TCP connect scan of the top 25 ports; 60-second timeout.
- **Standard service review**: TCP connect and light service detection of the top 100 ports; 150-second timeout.
- **Comprehensive inventory**: TCP connect and light service detection of ports 1 through 1024; 240-second timeout.

Nmap XML is parsed and only ports reported `open` become observations. The scanner records port, protocol, service label, and state. A label may be inferred from the port, particularly in Safe discovery. Nmap reachability and service detection do not establish vulnerable software, weak configuration, valid authorization, or organizational compliance. For example, an HTTPS port does not verify TLS, and an SMB port does not reveal share permissions.

## Framework mapping methodology

NIST Cybersecurity Framework **2.0** is the primary reference. CIS Controls **v8.1** provides secondary safeguards where the observed service warrants them. New findings show concise references under **Potential Framework Alignment**. Expand **Why and next checks** for the official wording, observed evidence, rationale, and verification steps. [Official NIST CSF 2.0 Core](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) · [CIS Controls v8.1 Navigator](https://www.cisecurity.org/controls/cis-controls-navigator)

- **Evidence-supported relevance** applies when service probing directly supports investigating an outcome. For example, a probe identifying a cleartext-capable service makes data-in-transit protection relevant to verify.
- **Potential control relevance** identifies a review prompted by listener reachability, such as checking approved configurations or authentication settings. Port-inferred service identities are marked unverified.

Both categories guide manual verification. Framework relevance does not establish compliance or noncompliance. Historical assessments retain their saved mappings.

## Status, policy priority, and vulnerability severity

- **Review required** means an observed exposure needs service-owner, baseline, configuration, or business-context verification. It does not mean a policy violation or vulnerability.
- **Baseline violation** is reserved for a rule explicitly configured with a violated requirement. The default service rules do not assume the organization prohibits a service; Telnet is therefore a high policy-priority review item, not an automatic violation.
- **Policy priority (High/Medium/Low)** is a fixed, deterministic rule label to order review. It is not a CVSS score, NIST score, or likelihood-impact calculation.
- **Vulnerability severity** is “Not assessed” unless a verified CVE record with a CVSS version, score, vector, and source is provided. Port and service names alone never imply a CVE. The interface follows [FIRST CVSS](https://www.first.org/cvss/) metadata concepts but has no vulnerability feed or external API.

[NIST SP 800-30 Rev. 1](https://csrc.nist.gov/pubs/sp/800/30/r1/final) describes risk assessment as a contextual process for organizations and information systems. Broader organizational risk decisions require evidence and assumptions about threats, vulnerabilities, likelihood, impact, and context; this scanner does not calculate a universal risk score from open ports.

## History comparison

An assessment detail page compares a completed real scan to the previous completed real assessment of the same target when available. It lists ports/services that appeared, disappeared, or remained present. These are observed changes only; they do not automatically prove remediation or improved security. Existing SQLite history is retained. New finding columns are added through an additive schema migration.

## Architecture and limitations

- `compliance_scanner/scanner.py`: fixed scan profiles, target validation, Nmap subprocess handling, and XML parsing.
- `compliance_scanner/policy_definitions.py` and `policy_engine.py`: service rules and evidence-based framework references.
- `compliance_scanner/risk_engine.py`: explainable policy-priority labels.
- `compliance_scanner/database.py`: SQLite persistence, additive migration, and same-target comparison.
- `compliance_scanner/routes.py`: dashboard, scan form, history, and assessment details.
- `templates/` and `static/`: existing dark dashboard and assessment presentation.

UDP scanning, subnet scanning, vulnerability detection, CVE enrichment, CSV export, accounts, and automated remediation are not implemented. No actual vulnerability score is generated by this phase.

## PDF assessment reports

Install the project dependencies, including ReportLab, in the project virtual environment:

```powershell
.venv\Scripts\python -m pip install -r requirements.txt
```

Open a completed assessment from the dashboard or history and select **Download PDF Report**. The report is generated from that assessment's stored SQLite record; it does not start another scan. It includes the original scan time, stored open-port findings, policy statuses and priorities, saved NIST CSF and CIS Controls references where available, evidence, remediation and manual verification guidance, and interpretation limits. High/Medium/Low values are policy priorities, not CVSS or official NIST ratings. An open port alone does not establish a vulnerability or policy violation.

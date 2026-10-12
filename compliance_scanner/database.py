"""SQLite persistence for assessments and their policy findings."""
import sqlite3
import json
import re
from pathlib import Path
from contextlib import closing


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(path)) as db, db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY, target TEXT NOT NULL, profile TEXT NOT NULL,
            status TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY, assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            port INTEGER NOT NULL, service TEXT NOT NULL, status TEXT NOT NULL, risk TEXT NOT NULL,
            explanation TEXT NOT NULL, risk_reason TEXT NOT NULL, recommendation TEXT NOT NULL,
            nist_csf TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at DESC);
        """)
        # Additive migration: retain existing assessment and finding history in place.
        existing = {row["name"] for row in db.execute("PRAGMA table_info(findings)")}
        additions = {
            "protocol": "TEXT NOT NULL DEFAULT 'tcp'",
            "observed_state": "TEXT NOT NULL DEFAULT 'open'",
            "observation": "TEXT NOT NULL DEFAULT ''",
            "why_matters": "TEXT NOT NULL DEFAULT ''",
            "verification": "TEXT NOT NULL DEFAULT ''",
            "violation_requirement": "TEXT",
            "legacy_status": "TEXT",
            "framework_mappings": "TEXT NOT NULL DEFAULT '[]'",
            "vulnerability_status": "TEXT NOT NULL DEFAULT 'not_assessed'",
            "cve": "TEXT",
            "cvss_version": "TEXT",
            "cvss_score": "REAL",
            "cvss_vector": "TEXT",
            "cvss_source": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in existing:
                db.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")
        # Earlier code auto-labeled Telnet a violation without an organizational baseline.
        # Preserve that historical label while presenting the item as a review requirement.
        db.execute("""UPDATE findings SET legacy_status=status,status='review',
            risk_reason='Legacy status was an automatic Telnet violation; no organization-specific baseline was recorded, so it now requires review.'
            WHERE port=23 AND lower(service)='telnet' AND status='violation'
            AND violation_requirement IS NULL AND observation='' AND legacy_status IS NULL""")


def create_assessment(path, target, profile, status="completed", is_demo=False, error=None, findings=()):
    with closing(connect(path)) as db, db:
        cur = db.execute("INSERT INTO assessments(target,profile,status,is_demo,error) VALUES(?,?,?,?,?)",
                         (target, profile, status, int(is_demo), error))
        assessment_id = cur.lastrowid
        db.executemany("""INSERT INTO findings(assessment_id,port,service,status,risk,explanation,risk_reason,recommendation,nist_csf,
            protocol,observed_state,observation,why_matters,verification,violation_requirement,legacy_status,framework_mappings,vulnerability_status,cve,cvss_version,cvss_score,cvss_vector,cvss_source)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", [_finding_values(assessment_id, f) for f in findings])
    return assessment_id


def list_assessments(path, limit=50):
    with closing(connect(path)) as db, db:
        rows = db.execute("SELECT * FROM assessments ORDER BY created_at DESC,id DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["findings"] = []
            for finding in db.execute("SELECT * FROM findings WHERE assessment_id=? ORDER BY port", (row["id"],)):
                parsed = dict(finding)
                try:
                    parsed["framework_mappings"] = json.loads(parsed.get("framework_mappings") or "[]")
                except (TypeError, json.JSONDecodeError):
                    parsed["framework_mappings"] = []
                item["findings"].append(parsed)
            result.append(item)
    return result


def _finding_values(assessment_id, finding):
    vulnerability = finding.get("vulnerability") or {}
    verified = vulnerability.get("verified") is True
    cve = vulnerability.get("cve") if verified else None
    version = vulnerability.get("cvss_version") if verified else None
    score = vulnerability.get("cvss_score") if verified else None
    vector = vulnerability.get("cvss_vector") if verified else None
    source = vulnerability.get("source") if verified else None
    valid_cve = isinstance(cve, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve)
    normalized_version = version.removeprefix("CVSS:") if isinstance(version, str) else ""
    valid_vector = (isinstance(vector, str) and
                    re.fullmatch(rf"CVSS:{re.escape(normalized_version)}/[A-Z]{{1,3}}:[A-Z](?:/[A-Z]{{1,3}}:[A-Z])+", vector))
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = None
    if not (valid_cve and normalized_version in {"3.0", "3.1", "4.0"} and valid_vector and
            score is not None and 0 <= score <= 10 and
            isinstance(source, str) and source.startswith("https://")):
        cve = version = score = vector = source = None
        vulnerability_status = "not_assessed"
    else:
        vulnerability_status = "verified"
    mappings = finding.get("framework_mappings", [])
    return (assessment_id, finding["port"], finding["service"], finding.get("status", "review"),
            finding.get("policy_priority", finding.get("risk", "Medium")), finding.get("explanation", ""),
            finding.get("risk_reason", ""), finding.get("recommendation", ""),
            ",".join(finding.get("nist_csf", [])), finding.get("protocol", "tcp"),
            finding.get("state", "open"), finding.get("observation", ""), finding.get("why_matters", finding.get("explanation", "")),
            finding.get("verification", ""), finding.get("violation_requirement"), None, json.dumps(mappings), vulnerability_status,
            cve, version, score, vector, source)


def compare_assessment(path, assessment_id):
    """Compare an assessment with its nearest earlier completed real scan of the same target."""
    with closing(connect(path)) as db:
        current = db.execute("SELECT * FROM assessments WHERE id=?", (assessment_id,)).fetchone()
        if current is None or current["is_demo"] or current["status"] != "completed":
            return None
        previous = db.execute("""SELECT * FROM assessments
            WHERE lower(target)=lower(?) AND id < ? AND is_demo=0 AND status='completed'
            ORDER BY id DESC LIMIT 1""", (current["target"], assessment_id)).fetchone()
        if previous is None:
            return None
        now_rows = db.execute("SELECT * FROM findings WHERE assessment_id=?", (assessment_id,)).fetchall()
        old_rows = db.execute("SELECT * FROM findings WHERE assessment_id=?", (previous["id"],)).fetchall()
    def indexed(rows):
        return {(row["protocol"] if "protocol" in row.keys() else "tcp", row["port"]): dict(row) for row in rows}
    now, old = indexed(now_rows), indexed(old_rows)
    return {
        "previous": dict(previous),
        "appeared": [now[key] for key in sorted(now.keys() - old.keys())],
        "disappeared": [old[key] for key in sorted(old.keys() - now.keys())],
        "remained": [{"current": now[key], "previous": old[key]} for key in sorted(now.keys() & old.keys())],
    }


def dashboard_summary(path):
    """Aggregate metrics over the full local history, independent of recent list limit."""
    with closing(connect(path)) as db:
        assessment_count = db.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
        finding_count = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        risks = {row["risk"]: row["amount"] for row in db.execute(
            "SELECT risk,COUNT(*) AS amount FROM findings GROUP BY risk")}
        review_count = db.execute("SELECT COUNT(*) FROM findings WHERE status='review'").fetchone()[0]
    return {"assessments": assessment_count, "findings": finding_count, "review": review_count,
            "risks": {name: risks.get(name, 0) for name in ("High", "Medium", "Low")}}

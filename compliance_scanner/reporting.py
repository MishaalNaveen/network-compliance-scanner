"""PDF reports generated from persisted assessment records."""
from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape


class ReportGenerator:
    """Render a stored assessment as a readable, paginated PDF."""

    def generate(self, assessment):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, HRFlowable
        except ImportError as exc:
            raise RuntimeError("PDF export requires ReportLab. Install project dependencies from requirements.txt.") from exc

        def value(obj, key, default=""):
            found = obj.get(key) if isinstance(obj, dict) else None
            return default if found is None or found == "" else str(found)

        findings = assessment.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        buffer = BytesIO()
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                                  fontSize=20, leading=24, textColor=colors.HexColor("#14243a"), spaceAfter=8))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontSize=13, leading=16,
                                  textColor=colors.HexColor("#155e75"), spaceBefore=12, spaceAfter=6))
        styles.add(ParagraphStyle(name="FindingTitle", parent=styles["Heading3"], fontSize=11, leading=14,
                                  textColor=colors.HexColor("#14243a"), spaceBefore=11, spaceAfter=4))
        styles.add(ParagraphStyle(name="SmallBody", parent=styles["BodyText"], fontSize=8.5, leading=11, spaceAfter=4))
        styles.add(ParagraphStyle(name="TableHead", parent=styles["BodyText"], fontName="Helvetica-Bold",
                                  fontSize=8.5, leading=11, textColor=colors.white))

        def para(text, style="SmallBody"):
            return Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style])

        def footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#d8e0e8"))
            canvas.line(0.65 * inch, 0.55 * inch, 7.85 * inch, 0.55 * inch)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748b"))
            canvas.drawString(0.68 * inch, 0.38 * inch, "Network Security Compliance Assessment")
            canvas.drawRightString(7.82 * inch, 0.38 * inch, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.68 * inch, leftMargin=0.68 * inch,
                                topMargin=0.62 * inch, bottomMargin=0.78 * inch,
                                title=f"Assessment {value(assessment, 'id', 'report')}",
                                author="Network Security Compliance Scanner")
        story = [para("Network Security Compliance Assessment", "ReportTitle"),
                 para(f"Generated: {generated}"),
                 HRFlowable(width="100%", thickness=1, color=colors.HexColor("#b9c8d8"), spaceAfter=9),
                 para("Assessment details", "Section")]
        details = [
            [para("Target", "TableHead"), para(value(assessment, "target", "Not recorded"))],
            [para("Original scan timestamp (UTC)", "TableHead"), para(value(assessment, "created_at", "Not recorded"))],
            [para("Scan profile", "TableHead"), para(value(assessment, "profile", "Not recorded"))],
            [para("Assessment status", "TableHead"), para(value(assessment, "status", "Not recorded"))],
            [para("Data type", "TableHead"), para("DEMO DATA" if assessment.get("is_demo") else "Recorded assessment")],
        ]
        details_table = Table(details, colWidths=[2.0 * inch, 4.65 * inch], hAlign="LEFT")
        details_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#155e75")),
            ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f2f6f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#d8e0e8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d8e0e8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.extend([details_table, para("Summary", "Section")])
        statuses = {"violation": 0, "review": 0}
        priorities = {"High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            status = value(finding, "status", "review").lower()
            if status in statuses:
                statuses[status] += 1
            priority = value(finding, "risk", value(finding, "policy_priority", ""))
            if priority in priorities:
                priorities[priority] += 1
        summary = Table([
            [para("Observed open ports", "TableHead"), para("Findings", "TableHead"),
             para("Policy status", "TableHead"), para("Policy priority", "TableHead")],
            [para(str(len(findings))), para(str(len(findings))),
             para(f"Violations: {statuses['violation']}; Review: {statuses['review']}"),
             para(f"High: {priorities['High']}; Medium: {priorities['Medium']}; Low: {priorities['Low']}")],
        ], colWidths=[1.35 * inch, 1.0 * inch, 1.85 * inch, 2.45 * inch], repeatRows=1)
        summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#155e75")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f2f6f9")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d8e0e8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.extend([summary, para("Detailed findings", "Section")])
        if not findings:
            story.append(para("No open ports or findings were stored for this assessment."))
        for index, finding in enumerate(findings, 1):
            port = value(finding, "port", "Unknown")
            service = value(finding, "service", "Unknown service")
            protocol = value(finding, "protocol", "unknown").upper()
            status = value(finding, "status", "review")
            status_label = "Baseline violation" if status == "violation" else "Review required"
            priority = value(finding, "risk", value(finding, "policy_priority", "Not recorded"))
            story.append(para(f"{index}. {protocol}/{port} - {service}", "FindingTitle"))
            story.append(para(f"Policy status: {status_label} | Policy priority: {priority}"))
            story.append(para(f"Observed state: {value(finding, 'observed_state', 'open')}"))
            story.append(para("Observed evidence: " + value(finding, "observation", "No evidence detail recorded.")))
            story.append(para("Assessment rationale: " + value(finding, "why_matters", value(finding, "explanation", "No rationale recorded."))))
            vulnerability = value(finding, "vulnerability_status", "not_assessed")
            if vulnerability == "verified" and value(finding, "cve"):
                cvss = f"; CVSS {value(finding, 'cvss_version')} {value(finding, 'cvss_score')}" if value(finding, "cvss_score") else ""
                story.append(para("Verified vulnerability record: " + value(finding, "cve") + cvss))
            else:
                story.append(para("Vulnerability: Not assessed; this service observation does not identify a verified CVE."))
            story.append(para("Recommended remediation: " + value(finding, "recommendation", "No recommendation recorded.")))
            story.append(para("Manual verification: " + value(finding, "verification", "Confirm service ownership, purpose, and approved exposure.")))
            if value(finding, "violation_requirement"):
                story.append(para("Configured requirement: " + value(finding, "violation_requirement")))
            mappings = finding.get("framework_mappings") or []
            story.append(para("Potential framework alignment"))
            if not isinstance(mappings, list) or not mappings:
                story.append(para("No direct mapping assigned."))
            else:
                for mapping in mappings:
                    if not isinstance(mapping, dict):
                        continue
                    if value(mapping, "framework"):
                        story.append(para(value(mapping, "framework") + " " + value(mapping, "version")))
                    story.append(para("Identifier: " + value(mapping, "identifier", "Not recorded") +
                                      " | Title: " + value(mapping, "title", "Not recorded")))
                    if value(mapping, "description"):
                        story.append(para(value(mapping, "description")))
                    if value(mapping, "category"):
                        story.append(para("Relevance category: " + value(mapping, "category")))
                    story.append(para("Rationale: " + value(mapping, "rationale", "No rationale recorded.")))
                    if value(mapping, "evidence"):
                        story.append(para("Observed evidence: " + value(mapping, "evidence")))
                    if value(mapping, "verification"):
                        story.append(para("Verify: " + value(mapping, "verification")))
                    if value(mapping, "evidence_limit"):
                        story.append(para("Evidence limit: " + value(mapping, "evidence_limit")))
        story.extend([para("Limitations and interpretation", "Section"),
                      para("This report summarizes stored scan observations and policy rules. An open port alone does not establish a vulnerability or a policy violation. A service label may be inferred from its port, and a network scan does not verify application configuration, business need, ownership, or organizational compliance."),
                      para("High, Medium, and Low are rule-based policy priorities for review. They are not CVSS scores or official NIST risk ratings. Framework relevance does not establish compliance or noncompliance. Manual verification by the responsible service owner is required.")])
        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return buffer.getvalue()

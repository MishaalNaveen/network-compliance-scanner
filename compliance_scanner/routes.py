"""Flask application factory and presentation routes."""
from flask import Flask, flash, make_response, redirect, render_template, request, url_for
from .database import compare_assessment, create_assessment, dashboard_summary, initialize, list_assessments
from .policy_engine import evaluate_services
from .scanner import PROFILES as SCAN_PROFILES, Scanner, ScannerError
from .reporting import ReportGenerator

PROFILES = {key: profile["label"] for key, profile in SCAN_PROFILES.items()}


def create_app(config=None):
    # This factory lives in a package while templates and static assets are project-level.
    app = Flask(__name__, template_folder="../templates", static_folder="../static",
                instance_relative_config=True)
    app.config.from_mapping(SECRET_KEY="development-only-change-me", DATABASE=str(app.instance_path + "/compliance.sqlite3"))
    if config:
        app.config.update(config)
    initialize(app.config["DATABASE"])
    scanner = app.config.get("SCANNER") or Scanner(executable=app.config.get("NMAP_EXECUTABLE"))

    @app.get("/")
    def dashboard():
        assessments = list_assessments(app.config["DATABASE"], 10)
        summary = dashboard_summary(app.config["DATABASE"])
        latest = next((a for a in assessments if not a["is_demo"] and a["status"] == "completed"), None)
        findings = latest["findings"] if latest else []
        counts = summary["risks"]
        latest_counts = {"violation": sum(f["status"] == "violation" for f in findings),
                         "review": sum(f["status"] == "review" for f in findings),
                         "mapped": sum(bool(f.get("framework_mappings")) for f in findings),
                         "verification": sum(f["status"] == "review" for f in findings),
                         "High": sum(f["risk"] == "High" for f in findings),
                         "Medium": sum(f["risk"] == "Medium" for f in findings),
                         "Low": sum(f["risk"] == "Low" for f in findings)}
        return render_template("dashboard.html", assessments=assessments, findings=findings[:8], counts=counts,
                               total=summary["assessments"], findings_count=summary["findings"],
                               review_count=summary["review"], latest=latest,
                               latest_open_ports=len(findings), latest_counts=latest_counts)

    @app.route("/scan", methods=["GET", "POST"])
    def scan():
        if request.method == "POST":
            target = request.form.get("target", "").strip()
            profile = request.form.get("profile", "")
            if request.form.get("authorized") != "yes":
                flash("Confirm that you own the target or have explicit authorization before scanning.", "error")
            elif profile not in PROFILES:
                flash("Choose one of the available scan profiles.", "error")
            else:
                try:
                    result = scanner.scan(target, profile)
                    findings = evaluate_services(result["observations"])
                    assessment_id = create_assessment(app.config["DATABASE"], result["target"], profile,
                                                      findings=findings)
                except (ScannerError, ValueError) as exc:
                    flash(str(exc), "error")
                else:
                    flash("Nmap assessment completed and saved.", "success")
                    return redirect(url_for("assessment_detail", assessment_id=assessment_id))
        return render_template("scan.html", profiles=PROFILES)

    @app.get("/history")
    def history():
        return render_template("history.html", assessments=list_assessments(app.config["DATABASE"], 100))

    @app.get("/assessments/<int:assessment_id>")
    def assessment_detail(assessment_id):
        item = next((a for a in list_assessments(app.config["DATABASE"], 1000) if a["id"] == assessment_id), None)
        if item is None:
            return render_template("not_found.html"), 404
        comparison = compare_assessment(app.config["DATABASE"], assessment_id)
        return render_template("assessment.html", assessment=item, comparison=comparison)

    @app.get("/assessments/<int:assessment_id>/report.pdf")
    def assessment_pdf(assessment_id):
        item = next((a for a in list_assessments(app.config["DATABASE"], 1000) if a["id"] == assessment_id), None)
        if item is None:
            return render_template("not_found.html"), 404
        pdf = ReportGenerator().generate(item)
        response = make_response(pdf)
        response.mimetype = "application/pdf"
        date = (item.get("created_at") or "").replace("-", "")[:8]
        suffix = f"-{date}" if len(date) == 8 and date.isdigit() else ""
        response.headers["Content-Disposition"] = f'attachment; filename="assessment-{assessment_id}{suffix}.pdf"'
        return response

    return app

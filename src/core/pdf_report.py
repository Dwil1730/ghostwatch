import json
import os
from datetime import datetime, timezone
from typing import Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from src.reporting.executive_report import build_executive_report

REPORT_DIR = "reports"


def generate_pdf_report(scan_data: Dict[str, Any]) -> str:
    os.makedirs(REPORT_DIR, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat().replace(":", "-").replace(".", "-")
    pdf_path = os.path.join(REPORT_DIR, f"ghostwatch_report_{timestamp}.pdf")

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()

    style_title = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#0A0A0A"),
        spaceAfter=4
    )
    style_subtitle = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        fontSize=11, textColor=colors.HexColor("#555555"),
        spaceAfter=16
    )
    style_h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#1A1A2E"),
        spaceBefore=14, spaceAfter=6
    )
    style_body = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=10, leading=14, textColor=colors.HexColor("#222222")
    )
    style_bullet = ParagraphStyle(
        "Bullet", parent=styles["Normal"],
        fontSize=10, leading=14, leftIndent=14,
        textColor=colors.HexColor("#222222")
    )

    exec_report = build_executive_report({"evidence": scan_data})
    summary = exec_report.get("executive_summary", {})
    meta = exec_report.get("report_metadata", {})
    recommendations = exec_report.get("recommendations", [])
    business_impact = exec_report.get("business_impact", {})

    results = scan_data.get("results", [])
    vulnerable = [r for r in results if r.get("detection_status") == "vulnerable"]
    safe = [r for r in results if r.get("detection_status") == "safe"]

    story = []

    story.append(Paragraph("GHOSTWATCH", style_title))
    story.append(Paragraph("AI Security Assessment Report", style_subtitle))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1A1A2E")))
    story.append(Spacer(1, 12))

    gen_at = meta.get("generated_at", datetime.now(timezone.utc).isoformat())
    meta_data = [
        ["Generated", gen_at[:19].replace("T", " ") + " UTC"],
        ["Report Type", meta.get("report_type", "AI Security Assessment")],
        ["Version", meta.get("version", "1.0")],
        ["Probes Run", str(len(results))],
        ["Vulnerable", str(len(vulnerable))],
        ["Safe", str(len(safe))],
    ]
    meta_table = Table(meta_data, colWidths=[1.4 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#111111")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Executive Summary", style_h2))
    risk_dist = summary.get("risk_distribution", {})
    summary_text = (
        f"This assessment executed <b>{len(results)} security probes</b> against the target AI system. "
        f"<b>{len(vulnerable)} vulnerabilities</b> were identified: "
        f"{risk_dist.get('high', 0)} HIGH, {risk_dist.get('medium', 0)} MEDIUM, "
        f"{risk_dist.get('low', 0)} LOW severity. "
        f"Average risk score: <b>{summary.get('average_risk_score', 0)}</b>/100."
    )
    story.append(Paragraph(summary_text, style_body))
    story.append(Spacer(1, 10))

    if vulnerable:
        story.append(Paragraph("Vulnerability Findings", style_h2))
        table_data = [["Probe", "Severity", "Score", "MITRE", "OWASP", "Indicators"]]
        for r in vulnerable:
            indicators = ", ".join(r.get("indicators", []))[:40]
            table_data.append([
                r.get("probe_type", ""),
                r.get("severity", "HIGH"),
                str(r.get("risk_score", 0)),
                r.get("mitre_id", ""),
                r.get("owasp_id", ""),
                indicators,
            ])
        findings_table = Table(table_data, colWidths=[1.2*inch, 0.8*inch, 0.5*inch, 1.0*inch, 0.7*inch, 2.5*inch])
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFF3F3"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("TEXTCOLOR", (1, 1), (1, -1), colors.HexColor("#CC0000")),
        ]))
        story.append(findings_table)
        story.append(Spacer(1, 12))

    story.append(Paragraph("Business Impact", style_h2))
    for key, val in business_impact.items():
        label = key.replace("_", " ").title()
        story.append(Paragraph(f"<b>{label}:</b> {val}", style_bullet))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Recommendations", style_h2))
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec}", style_bullet))
    story.append(Spacer(1, 10))

    story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "CONFIDENTIAL — GhostWatch AI Security Assessment | For authorized use only",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8,
                       textColor=colors.HexColor("#999999"), alignment=TA_CENTER)
    ))

    doc.build(story)
    return pdf_path

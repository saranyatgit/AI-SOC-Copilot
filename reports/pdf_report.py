import os

from reportlab.platypus import SimpleDocTemplate
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet


def generate_report(
        destination_port,
        flow_duration,
        prediction,
        risk,
        explanation,
        tactic,
        technique,
        technique_id,
        description,
        mitigation):

    os.makedirs("reports/generated", exist_ok=True)

    pdf = SimpleDocTemplate(
        "reports/generated/Incident_Report.pdf"
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph("<b>AI SOC Incident Report</b>", styles["Title"])
    )

    content.append(
        Paragraph(f"<b>Destination Port:</b> {destination_port}",
                  styles["Normal"])
    )

    content.append(
        Paragraph(f"<b>Flow Duration:</b> {flow_duration}",
                  styles["Normal"])
    )

    content.append(
        Paragraph(f"<b>Prediction:</b> {prediction}",
                  styles["Normal"])
    )

    content.append(
        Paragraph(f"<b>Risk Level:</b> {risk}",
                  styles["Normal"])
    )

    content.append(
        Paragraph("<b>MITRE ATT&CK Mapping</b>",
                  styles["Heading1"])
    )

    content.append(
        Paragraph(f"<b>Tactic:</b> {tactic}",
                  styles["Normal"])
    )

    content.append(
        Paragraph(f"<b>Technique:</b> {technique}",
                  styles["Normal"])
    )

    content.append(
        Paragraph(f"<b>Technique ID:</b> {technique_id}",
                  styles["Normal"])
    )

    content.append(
        Paragraph(f"<b>Description:</b> {description}",
                  styles["Normal"])
    )

    content.append(
        Paragraph(f"<b>Mitigation:</b> {mitigation}",
                  styles["Normal"])
    )

    content.append(
        Paragraph("<b>AI Threat Explanation</b>",
                  styles["Heading1"])
    )

    content.append(
        Paragraph(explanation,
                  styles["Normal"])
    )

    pdf.build(content)

    print("Incident Report Generated Successfully!")
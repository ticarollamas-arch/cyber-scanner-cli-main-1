"""PDF report generator using reportlab."""
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Preformatted,
)


SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#FF3B30"),
    "HIGH": colors.HexColor("#FFB800"),
    "MEDIUM": colors.HexColor("#007AFF"),
    "LOW": colors.HexColor("#8E8E93"),
    "INFO": colors.HexColor("#8E8E93"),
}


def build_pdf(scan: dict, findings: list) -> bytes:
    """Return PDF bytes for a scan + its findings."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2.5 * cm, rightMargin=2.5 * cm,
        topMargin=2.5 * cm, bottomMargin=2.5 * cm,
        title=f"VulnScan Report - {scan.get('project_name', '')}",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"], textColor=colors.HexColor("#0A0A0A"), spaceAfter=12)
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=colors.HexColor("#111111"), spaceAfter=10)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#333333"), spaceAfter=8)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=10, leading=14)
    code = ParagraphStyle("Code", parent=styles["Code"], fontSize=8, leading=11, textColor=colors.HexColor("#111"))

    story = []
    story.append(Paragraph("VulnScan AI · Security Assessment Report", title_style))
    story.append(Paragraph(f"Project: <b>{scan.get('project_name','-')}</b>", body))
    story.append(Paragraph(f"Scan ID: {scan.get('id','-')}", body))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body))
    story.append(Spacer(1, 0.5 * cm))

    # Summary table
    counts = scan.get("counts", {})
    summary_data = [
        ["Severity", "Count"],
        ["CRITICAL", str(counts.get("CRITICAL", 0))],
        ["HIGH", str(counts.get("HIGH", 0))],
        ["MEDIUM", str(counts.get("MEDIUM", 0))],
        ["LOW", str(counts.get("LOW", 0))],
        ["TOTAL", str(len(findings))],
    ]
    t = Table(summary_data, colWidths=[6 * cm, 3 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
    ]))
    story.append(Paragraph("Executive Summary", h1))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Findings Overview", h1))
    if not findings:
        story.append(Paragraph("No vulnerabilities detected.", body))
    else:
        rows = [["#", "Severity", "Scanner", "Title", "File"]]
        for i, f in enumerate(findings[:80], 1):
            rows.append([str(i), f.get("severity", "-"), f.get("scanner", "-"),
                         (f.get("title", "-") or "-")[:60],
                         (f.get("file_path", "-") or "-")[:50]])
        t2 = Table(rows, colWidths=[0.8 * cm, 2 * cm, 2 * cm, 7 * cm, 4 * cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DDDDDD")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t2)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", h1))
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "MEDIUM")
        story.append(Paragraph(f"[{f.get('priority','P3')}] {i}. {f.get('title','-')}", h2))
        meta = f"<b>Severity:</b> {sev} · <b>Scanner:</b> {f.get('scanner','')} · <b>Rule:</b> {f.get('rule_id','')}"
        story.append(Paragraph(meta, body))
        story.append(Paragraph(f"<b>File:</b> {f.get('file_path','-')}:{f.get('line_start','-')}", body))
        if f.get("cwe"):
            story.append(Paragraph(f"<b>CWE:</b> {f['cwe']}", body))
        story.append(Paragraph("<b>Description</b>", body))
        story.append(Paragraph((f.get("description") or "-").replace("\n", "<br/>"), body))

        ai = f.get("ai_analysis") or {}
        if ai.get("impact"):
            story.append(Paragraph("<b>Impact</b>", body))
            story.append(Paragraph(ai["impact"], body))
        if ai.get("root_cause"):
            story.append(Paragraph("<b>Root Cause</b>", body))
            story.append(Paragraph(ai["root_cause"], body))
        if f.get("code_snippet"):
            story.append(Paragraph("<b>Code Snippet</b>", body))
            snippet = (f.get("code_snippet") or "")[:1200]
            story.append(Preformatted(snippet, code))
        if ai.get("poc_commands"):
            story.append(Paragraph("<b>Proof of Concept (Reproducible)</b>", body))
            for step in ai["poc_commands"]:
                desc = step.get("description", "")
                cmd = step.get("command", "")
                story.append(Paragraph(f"<b>Step {step.get('step','')}:</b> {desc}", body))
                story.append(Preformatted(cmd[:600], code))
        if ai.get("remediation"):
            story.append(Paragraph("<b>Remediation</b>", body))
            story.append(Paragraph(str(ai["remediation"])[:2000], body))
        if ai.get("patch_diff"):
            story.append(Paragraph("<b>Patch Diff</b>", body))
            story.append(Preformatted(str(ai["patch_diff"])[:1500], code))
        story.append(Spacer(1, 0.4 * cm))

    doc.build(story)
    return buffer.getvalue()


def build_markdown(scan: dict, findings: list) -> str:
    out = []
    out.append(f"# VulnScan AI · Security Assessment Report\n")
    out.append(f"**Project:** {scan.get('project_name','-')}  \n")
    out.append(f"**Scan ID:** `{scan.get('id','-')}`  \n")
    out.append(f"**Generated:** {datetime.utcnow().isoformat()}Z  \n\n")

    counts = scan.get("counts", {})
    out.append("## Executive Summary\n\n")
    out.append("| Severity | Count |\n|---|---|\n")
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        out.append(f"| {s} | {counts.get(s, 0)} |\n")
    out.append(f"| **TOTAL** | **{len(findings)}** |\n\n")

    out.append("## Detailed Findings\n\n")
    for i, f in enumerate(findings, 1):
        out.append(f"### {i}. [{f.get('priority','P3')}] {f.get('title','-')}\n\n")
        out.append(f"- **Severity:** {f.get('severity','-')}\n")
        out.append(f"- **Scanner:** {f.get('scanner','-')}\n")
        out.append(f"- **Rule:** `{f.get('rule_id','-')}`\n")
        out.append(f"- **File:** `{f.get('file_path','-')}:{f.get('line_start','-')}`\n")
        if f.get("cwe"):
            out.append(f"- **CWE:** {f['cwe']}\n")
        out.append(f"\n**Description**\n\n{f.get('description','')}\n\n")
        ai = f.get("ai_analysis") or {}
        if ai.get("impact"):
            out.append(f"**Impact**\n\n{ai['impact']}\n\n")
        if ai.get("root_cause"):
            out.append(f"**Root Cause**\n\n{ai['root_cause']}\n\n")
        if f.get("code_snippet"):
            out.append(f"**Code**\n\n```\n{f['code_snippet']}\n```\n\n")
        if ai.get("poc_commands"):
            out.append("**Proof of Concept (Reproducible)**\n\n")
            for step in ai["poc_commands"]:
                out.append(f"Step {step.get('step','')}: {step.get('description','')}\n\n")
                out.append(f"```bash\n{step.get('command','')}\n```\n\n")
                if step.get("expected_output"):
                    out.append(f"_Expected:_ `{step['expected_output']}`\n\n")
        if ai.get("remediation"):
            out.append(f"**Remediation**\n\n{ai['remediation']}\n\n")
        if ai.get("patch_diff"):
            out.append(f"```diff\n{ai['patch_diff']}\n```\n\n")
    return "".join(out)

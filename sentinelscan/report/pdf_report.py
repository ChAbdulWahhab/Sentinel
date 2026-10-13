"""PDF report (requires reportlab)."""
from __future__ import annotations
from sentinelscan.core.findings import ScanResult
from sentinelscan.report.base import BaseReporter


class PdfReporter(BaseReporter):
    extension = "pdf"

    def render(self, result: ScanResult) -> str:
        raise NotImplementedError

    def write(self, result: ScanResult, path):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import cm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib import colors
        except ImportError:
            raise RuntimeError("PDF ke liye: pip install reportlab")

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(str(path), pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        story = []
        story.append(Paragraph(f"<b>SentinelScan Report</b>", styles["Title"]))
        story.append(Paragraph(f"Target: {result.target}", styles["Normal"]))
        story.append(Paragraph(f"Date: {result.timestamp:%Y-%m-%d %H:%M}", styles["Normal"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Summary", styles["Heading2"]))
        counts = result.counts()
        data = [["Severity", "Count"]] + [[s.name, n] for s, n in counts.items()]
        t = Table(data, colWidths=[6*cm, 4*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        story.append(Paragraph("Findings", styles["Heading2"]))
        for i, f in enumerate(sorted(result.findings, key=lambda x: x.severity), 1):
            story.append(Paragraph(f"<b>{i}. [{f.severity.name}] {f.title}</b>", styles["Heading3"]))
            story.append(Paragraph(f"Module: {f.module}", styles["Normal"]))
            if f.url:
                story.append(Paragraph(f"URL: {f.url}", styles["Normal"]))
            story.append(Paragraph(f"Detail: {f.detail}", styles["Normal"]))
            if f.fix:
                story.append(Paragraph(f"Fix: {f.fix}", styles["Normal"]))
            story.append(Spacer(1, 8))

        doc.build(story)
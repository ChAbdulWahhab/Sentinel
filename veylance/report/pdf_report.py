"""PDF report matching Veylance's visual identity (requires reportlab)."""
from __future__ import annotations

from veylance.config import LEGAL_NOTICE, REPORT_DISCLAIMER, VERSION
from veylance.core.findings import ScanResult, Severity
from veylance.report.base import BaseReporter


class PdfReporter(BaseReporter):
    extension = "pdf"

    def render(self, result: ScanResult) -> str:
        raise NotImplementedError("PDF is generated directly to binary file.")

    def write(self, result: ScanResult, path):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import cm
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        except ImportError:
            raise RuntimeError("PDF output requires reportlab: pip install reportlab")

        styles = getSampleStyleSheet()

        # Custom Veylance typography styles
        title_style = ParagraphStyle(
            "VeylanceTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#09090b"),
            alignment=0,
        )
        subtitle_style = ParagraphStyle(
            "VeylanceSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            textColor=colors.HexColor("#71717a"),
            leading=14,
        )
        h2_style = ParagraphStyle(
            "VeylanceH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#09090b"),
            spaceBefore=14,
            spaceAfter=6,
        )
        finding_title_style = ParagraphStyle(
            "FindingTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#18181b"),
        )
        meta_style = ParagraphStyle(
            "MetaStyle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#3f3f46"),
        )
        fix_style = ParagraphStyle(
            "FixStyle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#166534"),
        )

        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=1.8 * cm,
            rightMargin=1.8 * cm,
            topMargin=1.8 * cm,
            bottomMargin=1.8 * cm,
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph('<font color="#dc2626"><b>Veylance</b></font> <b>Security Report</b>', title_style))
        story.append(Paragraph(f"Website Security Audit Engine &bull; v{VERSION} &bull; 35 Security Modules Active", subtitle_style))
        story.append(Spacer(1, 10))

        # 2. Audit Metadata Box
        meta_data = [
            [Paragraph(f"<b>Target:</b> {result.target}", meta_style), Paragraph(f"<b>Audit Date:</b> {result.timestamp:%Y-%m-%d %H:%M} UTC", meta_style)],
            [Paragraph(f"<b>Duration:</b> {result.duration:.2f}s", meta_style), Paragraph(f"<b>Total Findings:</b> {len(result.findings)}", meta_style)],
        ]
        meta_table = Table(meta_data, colWidths=[9 * cm, 8.4 * cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f4f5")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e4e4e7")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e4e4e7")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # 3. Legal Notice Banner
        story.append(Paragraph(f"<b>Legal Authorization & Scope:</b> {LEGAL_NOTICE}", meta_style))
        story.append(Spacer(1, 12))

        # 4. Findings Summary Table
        story.append(Paragraph("Severity Summary", h2_style))
        counts = result.counts()
        sev_hexes = {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#f59e0b",
            Severity.LOW: "#2563eb",
            Severity.INFO: "#71717a",
        }
        data = [["Severity Level", "Discovered Count"]]
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            n = counts.get(s, 0)
            data.append([s.name, str(n)])

        t = Table(data, colWidths=[6 * cm, 4 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dc2626")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e4e4e7")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

        # 5. Detailed Findings List
        story.append(Paragraph(f"Actionable Findings ({len(result.findings)})", h2_style))
        for i, f in enumerate(sorted(result.findings, key=lambda x: x.severity), 1):
            sev_color = sev_hexes.get(f.severity, "#dc2626")
            story.append(Paragraph(
                f'<b>{i}. <font color="{sev_color}">[{f.severity.name}]</font> {f.title}</b> (module: <i>{f.module}</i>)',
                finding_title_style,
            ))
            if f.url:
                story.append(Paragraph(f"<b>Endpoint:</b> {f.url}", meta_style))
            story.append(Paragraph(f"<b>Detail:</b> {f.detail}", meta_style))
            if f.fix:
                story.append(Paragraph(f"<b>Remediation:</b> {f.fix}", fix_style))
            if f.evidence:
                story.append(Paragraph(f"<b>Evidence:</b> {f.evidence[:300]}", meta_style))
            story.append(Spacer(1, 6))

        story.append(Spacer(1, 14))
        story.append(Paragraph(f"<b>Disclaimer:</b> {REPORT_DISCLAIMER}", meta_style))

        doc.build(story)
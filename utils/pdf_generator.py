import io
from datetime import datetime

class PurePythonPDFBuilder:
    """Zero-dependency, pure Python PDF-1.4 binary builder that outputs 100% valid PDF documents."""
    def build_report_pdf(self, scan_data: dict, candidate_name: str = "Candidate") -> bytes:
        company = str(scan_data.get('company', 'N/A'))
        job_title = str(scan_data.get('job_title', 'N/A'))
        risk_status = str(scan_data.get('risk_status', 'Unknown'))
        risk_score = f"{scan_data.get('risk_score', 0.0):.1f}%"
        confidence = f"{scan_data.get('confidence', 0.0):.1f}%"
        scam_category = str(scan_data.get('scam_category', 'General'))
        keywords = scan_data.get('flagged_keywords_list', [])
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        def clean(txt):
            if not txt:
                return ""
            return str(txt).replace('\\', '/').replace('(', '[').replace(')', ']')[:65]

        ops = []
        ops.append("BT /F2 18 Tf 50 740 Td (JOBSHYLD AI - FORENSIC SECURITY AUDIT REPORT) Tj ET")
        ops.append("BT /F1 9 Tf 50 722 Td (Official Candidate Certificate | Generated: " + timestamp + " UTC) Tj ET")
        ops.append("0.7 0.7 0.7 RG 1 w 50 710 m 560 710 l S")
        ops.append("0.95 0.97 0.99 rg 50 560 510 135 re f")
        ops.append("0.8 0.85 0.9 RG 1 w 50 560 510 135 re S")
        ops.append("BT /F2 11 Tf 65 670 Td (Candidate Name:) Tj ET")
        ops.append("BT /F1 11 Tf 180 670 Td (" + clean(candidate_name) + ") Tj ET")
        ops.append("BT /F2 11 Tf 65 650 Td (Company Name:) Tj ET")
        ops.append("BT /F1 11 Tf 180 650 Td (" + clean(company) + ") Tj ET")
        ops.append("BT /F2 11 Tf 65 630 Td (Job Position:) Tj ET")
        ops.append("BT /F1 11 Tf 180 630 Td (" + clean(job_title) + ") Tj ET")
        ops.append("BT /F2 11 Tf 65 610 Td (Audit Status:) Tj ET")
        status_color = "0.9 0.1 0.1 rg" if risk_status == "Scam" else "0.1 0.7 0.3 rg"
        ops.append("BT " + status_color + " /F2 12 Tf 180 610 Td (" + risk_status.upper() + " - Scam Risk: " + risk_score + ") Tj ET")
        ops.append("BT /F2 11 Tf 65 590 Td (Detection Confidence:) Tj ET")
        ops.append("BT /F1 11 Tf 180 590 Td (" + confidence + ") Tj ET")
        ops.append("BT /F2 11 Tf 65 570 Td (Scam Category:) Tj ET")
        ops.append("BT /F1 11 Tf 180 570 Td (" + clean(scam_category) + ") Tj ET")
        ops.append("0 0 0 rg")
        ops.append("BT /F2 13 Tf 50 525 Td (1. Threat Signals & Flagged Indicators) Tj ET")
        y = 505
        if keywords:
            for kw in keywords[:5]:
                ops.append(f"BT 0.9 0.1 0.1 rg /F2 10 Tf 65 {y} Td ([FLAGGED THREAT]) Tj 0 0 0 rg /F1 10 Tf 170 {y} Td ({clean(kw)}) Tj ET")
                y -= 18
        else:
            ops.append(f"BT 0.1 0.7 0.3 rg /F2 10 Tf 65 {y} Td ([NO THREATS]) Tj 0 0 0 rg /F1 10 Tf 150 {y} Td (Zero suspicious fraud indicators detected.) Tj ET")
            y -= 18

        y -= 15
        ops.append(f"BT /F2 13 Tf 50 {y} Td (2. Candidate Safety Verification Instructions) Tj ET")
        y -= 20
        recs = [
            "Verify recruiter email domain matches official corporate website.",
            "Never send registration fees, laptop deposits, or crypto payments.",
            "Avoid interviews conducted solely on informal chat apps."
        ]
        for rec in recs:
            ops.append(f"BT /F1 10 Tf 65 {y} Td (- {clean(rec)}) Tj ET")
            y -= 18

        ops.append("0.7 0.7 0.7 RG 1 w 50 70 m 560 70 l S")
        ops.append("BT /F1 8 Tf 50 55 Td (This certificate was issued by JobShyld AI Hybrid Threat Inspection Engine. Verification Code: JS-2026-AUDIT) Tj ET")

        stream_bytes = "\n".join(ops).encode('latin1')
        obj1 = "<< /Type /Catalog /Pages 2 0 R >>"
        obj2 = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
        obj3 = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>"
        obj4 = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        obj5 = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        obj6 = f"<< /Length {len(stream_bytes)} >>\nstream\n" + stream_bytes.decode('latin1') + "\nendstream"

        objects = [obj1, obj2, obj3, obj4, obj5, obj6]

        out = io.BytesIO()
        out.write(b"%PDF-1.4\n")
        offsets = [0]
        for idx, obj in enumerate(objects, 1):
            offsets.append(out.tell())
            out.write(f"{idx} 0 obj\n{obj}\nendobj\n".encode('latin1'))

        xref_offset = out.tell()
        out.write(f"xref\n0 {len(objects) + 1}\n".encode('latin1'))
        out.write(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            out.write(f"{off:010d} 00000 n \n".encode('latin1'))

        out.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode('latin1'))
        return out.getvalue()


def generate_pdf_report(scan_data: dict, candidate_name: str = "Candidate") -> bytes:
    """
    Generate formal PDF security audit report using ReportLab if available, or PurePythonPDFBuilder fallback.
    Always returns valid %PDF-1.4 binary bytes.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=colors.HexColor('#0284c7'))
        heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=colors.HexColor('#0f172a'))
        body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, textColor=colors.HexColor('#334155'))
        scam_style = ParagraphStyle('ScamStyle', fontName='Helvetica-Bold', fontSize=14, textColor=colors.HexColor('#ef4444'))
        safe_style = ParagraphStyle('SafeStyle', fontName='Helvetica-Bold', fontSize=14, textColor=colors.HexColor('#10b981'))

        story.append(Paragraph("<b>JOBSHYLD AI — FORENSIC SECURITY AUDIT REPORT</b>", title_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"Official Job Scam Audit Certificate | Candidate: {candidate_name} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", body_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0284c7'), spaceAfter=15))

        risk_status = scan_data.get('risk_status', 'Unknown')
        risk_score = scan_data.get('risk_score', 0.0)
        status_paragraph = Paragraph(f"<b>{risk_status.upper()} ({risk_score:.1f}% Scam Risk)</b>", scam_style if risk_status == "Scam" else safe_style)

        summary_table_data = [
            [Paragraph("<b>Company Name:</b>", body_style), Paragraph(str(scan_data.get('company', 'N/A')), body_style)],
            [Paragraph("<b>Job Role:</b>", body_style), Paragraph(str(scan_data.get('job_title', 'N/A')), body_style)],
            [Paragraph("<b>Audit Status:</b>", body_style), status_paragraph],
            [Paragraph("<b>Detection Confidence:</b>", body_style), Paragraph(f"{scan_data.get('confidence', 0.0):.1f}%", body_style)],
            [Paragraph("<b>Scam Category:</b>", body_style), Paragraph(str(scan_data.get('scam_category', 'General')), body_style)]
        ]

        t = Table(summary_table_data, colWidths=[150, 390])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 15))

        story.append(Paragraph("<b>1. Threat Signals & Flagged Indicators</b>", heading_style))
        story.append(Spacer(1, 5))
        keywords = scan_data.get('flagged_keywords_list', [])
        if keywords:
            for kw in keywords:
                story.append(Paragraph(f"• <font color='#ef4444'><b>[FLAGGED THREAT]</b></font> {kw}", body_style))
        else:
            story.append(Paragraph("• <font color='#10b981'><b>[NO THREATS]</b></font> Zero suspicious fraud indicators detected.", body_style))
        story.append(Spacer(1, 15))

        story.append(Paragraph("<b>2. Candidate Actionable Safety Instructions</b>", heading_style))
        story.append(Spacer(1, 5))
        recs = scan_data.get('recommendations', []) or [
            "Verify recruiter email domain against official corporate website.",
            "Never send money, registration fees, or equipment deposits.",
            "Avoid interviews conducted solely on informal chat apps (Telegram/WhatsApp)."
        ]
        for rec in recs:
            story.append(Paragraph(f"✓ {rec}", body_style))

        story.append(Spacer(1, 25))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
        story.append(Paragraph("<i>This security report was generated by JobShyld AI Hybrid Machine Learning Engine. Document verification code: JS-AUDIT-2026.</i>", body_style))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
    except Exception as e:
        print(f"[PDF Generator] Using PurePythonPDFBuilder fallback due to: {e}")
        return PurePythonPDFBuilder().build_report_pdf(scan_data, candidate_name)

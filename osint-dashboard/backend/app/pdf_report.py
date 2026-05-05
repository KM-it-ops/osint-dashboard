"""
Build PDF documents for saved Live Target Analyzer reports (reportlab).

Used by ``GET /api/report/pdf/{report_id}``.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def _safe_url(url: str) -> str:
    u = (url or "").strip()
    if u.startswith(("http://", "https://")) and len(u) < 2048:
        return u
    return ""


def build_intel_report_pdf(row: dict[str, Any]) -> bytes:
    """
    Render one intel report PDF from a row dict returned by ``get_target_report``.
    Sections: metadata, summary, key findings, sources (titles + URLs).
    """
    rep = row.get("report") if isinstance(row.get("report"), dict) else {}
    rid = row.get("id", "")
    target_raw = str(row.get("target_raw") or "")
    target_type = str(row.get("target_type") or "")
    query_used = str(row.get("query_used") or "")
    created_at = str(row.get("created_at") or "")
    summary = str(rep.get("summary") or "")
    findings = rep.get("key_findings")
    if not isinstance(findings, list):
        findings = []
    sources = rep.get("sources")
    if not isinstance(sources, list):
        sources = []

    kind_norm = str(rep.get("target_kind") or "")
    canon = str(rep.get("target_normalized") or "")

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        title=f"Intel report {rid}",
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name="IntelTitle",
        parent=styles["Heading1"],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor("#0f172a"),
    )
    h2_style = ParagraphStyle(
        name="IntelH2",
        parent=styles["Heading2"],
        fontSize=11,
        spaceBefore=14,
        spaceAfter=8,
        textColor=colors.HexColor("#1e293b"),
    )
    body = ParagraphStyle(
        name="IntelBody",
        parent=styles["Normal"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    muted = ParagraphStyle(
        name="IntelMuted",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#64748b"),
    )

    story: list[Any] = []
    story.append(Paragraph("Target intelligence report", title_style))
    story.append(Spacer(1, 0.1 * inch))

    meta_lines = [
        f"<b>Report ID:</b> {escape(str(rid))}",
        f"<b>Generated (saved):</b> {escape(created_at)}",
        f"<b>Target:</b> {escape(target_raw)}",
        f"<b>Target type:</b> {escape(target_type)}",
    ]
    if canon:
        meta_lines.append(f"<b>Normalized target:</b> {escape(canon)}")
    if kind_norm:
        meta_lines.append(f"<b>Classified kind:</b> {escape(kind_norm)}")
    meta_lines.append(f"<b>Query used:</b> {escape(query_used)}")
    for line in meta_lines:
        story.append(Paragraph(line, muted))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("Summary", h2_style))
    story.append(Paragraph(escape(summary) or "(No summary.)", body))

    story.append(Paragraph("Key findings", h2_style))
    if findings:
        for item in findings[:24]:
            t = str(item).strip()
            if t:
                story.append(Paragraph(f"• {escape(t)}", body))
    else:
        story.append(Paragraph("(None listed.)", body))

    story.append(Paragraph("Sources", h2_style))
    if sources:
        for i, src in enumerate(sources[:30], start=1):
            if not isinstance(src, dict):
                continue
            title = escape(str(src.get("title") or "Untitled").strip() or "Untitled")
            url = _safe_url(str(src.get("url") or ""))
            snippet = str(src.get("snippet") or "").strip()
            if snippet and len(snippet) > 400:
                snippet = snippet[:397] + "..."
            sn_esc = escape(snippet) if snippet else ""

            if url:
                # Paragraph link: escape URL for XML attribute
                url_esc = escape(url, {"'": "&apos;", '"': "&quot;"})
                line = (
                    f'{i}. <a href="{url_esc}" color="blue">{title}</a>'
                    + (f"<br/><i>{sn_esc}</i>" if sn_esc else "")
                )
            else:
                line = f"{i}. {title}" + (f"<br/><i>{sn_esc}</i>" if sn_esc else "")
            story.append(Paragraph(line, body))
            story.append(Spacer(1, 0.06 * inch))
    else:
        story.append(Paragraph("(None listed.)", body))

    footer_note = (
        "KM-IT-Ops OSINT Dashboard — synthesized from Firecrawl open-web snapshot. "
        "Verify URLs and claims independently."
    )
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(f"<i>{escape(footer_note)}</i>", muted))

    doc.build(story)
    return buf.getvalue()

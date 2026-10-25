"""
OmniSight-OSINT Technical Documentation PDF Generator
======================================================
Compiles publication-grade system documentation, architecture diagrams,
core infrastructure, module deep-dives, accuracy metrics, and the
terminal startup interface into an official PDF document using ReportLab.

Author: Muhammad Inaam Kaleem
Institution: Riphah International University Faisalabad
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfgen import canvas

# ─── Font Registration (Consolas & Arial with fallback) ───────────────────────
FONT_MONO = "Courier"
FONT_SANS = "Helvetica"
FONT_SANS_BOLD = "Helvetica-Bold"

windir = os.environ.get("WINDIR", "C:\\Windows")
fonts_dir = Path(windir) / "Fonts"

try:
    consola_path = fonts_dir / "consola.ttf"
    if consola_path.is_file():
        pdfmetrics.registerFont(TTFont("Consolas", str(consola_path)))
        FONT_MONO = "Consolas"
except Exception:
    pass

try:
    arial_path = fonts_dir / "arial.ttf"
    arial_bd_path = fonts_dir / "arialbd.ttf"
    if arial_path.is_file() and arial_bd_path.is_file():
        pdfmetrics.registerFont(TTFont("Arial", str(arial_path)))
        pdfmetrics.registerFont(TTFont("Arial-Bold", str(arial_bd_path)))
        FONT_SANS = "Arial"
        FONT_SANS_BOLD = "Arial-Bold"
except Exception:
    pass

# ─── Color Palette ─────────────────────────────────────────────────────────────
NAVY_DARK   = colors.HexColor("#0B132B")
NAVY_MED    = colors.HexColor("#1C2541")
CYAN_ACCENT = colors.HexColor("#0077B6")
CYAN_LIGHT  = colors.HexColor("#E0F2FE")
TEAL_GREEN  = colors.HexColor("#028090")
ALERT_RED   = colors.HexColor("#D90429")
ALERT_BG    = colors.HexColor("#FDE8E8")
CHARCOAL    = colors.HexColor("#2B2D42")
GRAY_LIGHT  = colors.HexColor("#F8F9FA")
GRAY_BORDER = colors.HexColor("#CBD5E1")
TERM_BG     = colors.HexColor("#0F172A")


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas calculating total pages for 'Page X of Y' footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        if self._pageNumber == 1:
            # Suppress running header/footer on title cover page
            return

        self.saveState()
        self.setFont(FONT_SANS_BOLD, 8)
        self.setFillColor(NAVY_MED)

        # Running Header
        self.drawString(54, 11 * inch - 36, "OMNISIGHT-OSINT  |  Technical Architecture & System Documentation")
        self.setFont(FONT_SANS, 8)
        self.setFillColor(colors.gray)
        self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "v1.0.0 -- Production Edition")

        self.setStrokeColor(GRAY_BORDER)
        self.setLineWidth(0.75)
        self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Running Footer
        self.line(54, 46, 8.5 * inch - 54, 46)
        self.setFont(FONT_SANS, 8)
        self.setFillColor(colors.dimgray)
        self.drawString(54, 32, "Author: Muhammad Inaam Kaleem  |  Riphah International University Faisalabad")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 32, page_str)
        self.restoreState()


def build_pdf(filename: str = "OmniSight_OSINT_Documentation.pdf") -> str:
    """Compile and generate the PDF documentation."""
    out_path = Path(filename).resolve()
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    style_title = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName=FONT_SANS_BOLD,
        fontSize=26,
        leading=32,
        textColor=NAVY_DARK,
        alignment=1,
    )

    style_subtitle = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName=FONT_SANS,
        fontSize=12,
        leading=16,
        textColor=CYAN_ACCENT,
        alignment=1,
    )

    style_h1 = ParagraphStyle(
        "SectionH1",
        parent=styles["Heading1"],
        fontName=FONT_SANS_BOLD,
        fontSize=14,
        leading=18,
        textColor=NAVY_DARK,
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True,
    )

    style_h2 = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontName=FONT_SANS_BOLD,
        fontSize=10.5,
        leading=14,
        textColor=NAVY_MED,
        spaceBefore=7,
        spaceAfter=3,
        keepWithNext=True,
    )

    style_body = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName=FONT_SANS,
        fontSize=8.5,
        leading=12,
        textColor=CHARCOAL,
        spaceAfter=4,
    )

    style_bullet = ParagraphStyle(
        "BulletText",
        parent=style_body,
        leftIndent=10,
        firstLineIndent=-6,
        spaceAfter=2,
    )

    style_code = ParagraphStyle(
        "CodeTerminal",
        parent=styles["Code"],
        fontName=FONT_MONO,
        fontSize=6.8,
        leading=8.6,
        textColor=colors.whitesmoke,
    )

    style_table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName=FONT_SANS_BOLD,
        fontSize=8,
        leading=10.5,
        textColor=colors.white,
        alignment=1,
    )

    style_table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName=FONT_SANS,
        fontSize=7.8,
        leading=10,
        textColor=CHARCOAL,
    )

    style_table_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=style_table_cell,
        fontName=FONT_SANS_BOLD,
    )

    story = []

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 1: COVER / TITLE PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 35))
    story.append(Paragraph("OMNISIGHT-OSINT", style_title))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Modular Cyber Reconnaissance &amp; Threat Intelligence Framework", style_subtitle))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="90%", thickness=2.5, color=CYAN_ACCENT, spaceBefore=4, spaceAfter=16))

    cover_table_data = [
        [Paragraph("<b>Document Classification</b>", style_table_cell_bold), Paragraph("Technical Architecture &amp; System Documentation (v1.0.0)", style_table_cell)],
        [Paragraph("<b>Lead Developer &amp; Author</b>", style_table_cell_bold), Paragraph("<b>Muhammad Inaam Kaleem</b>", style_table_cell)],
        [Paragraph("<b>Academic Institution</b>", style_table_cell_bold), Paragraph("Riphah International University Faisalabad", style_table_cell)],
        [Paragraph("<b>Academic Program</b>", style_table_cell_bold), Paragraph("Cybersecurity &amp; Information Assurance", style_table_cell)],
        [Paragraph("<b>Engineering Stack</b>", style_table_cell_bold), Paragraph("Python 3.10+ | Pure Async (aiohttp, asyncio) | Pydantic v2 | Rich CLI", style_table_cell)],
        [Paragraph("<b>Release Status</b>", style_table_cell_bold), Paragraph("Production-Ready Open-Source Reconnaissance Suite", style_table_cell)],
        [Paragraph("<b>License</b>", style_table_cell_bold), Paragraph("MIT Open-Source License", style_table_cell)],
        [Paragraph("<b>Publication Date</b>", style_table_cell_bold), Paragraph(datetime.now().strftime("%B %Y"), style_table_cell)],
    ]
    cover_table = Table(cover_table_data, colWidths=[2.2 * inch, 4.3 * inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), GRAY_LIGHT),
        ("TEXTCOLOR", (0, 0), (-1, -1), CHARCOAL),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("BOX", (0, 0), (-1, -1), 1.5, CYAN_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 6.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(cover_table)

    story.append(Spacer(1, 20))

    notice_text = (
        "<b>RESTRICTED TESTING &amp; OPERATIONAL COMPLIANCE NOTICE:</b><br/>"
        "This software and architectural specification are engineered strictly for authorized security auditing, "
        "academic research, and defensive threat intelligence. Use this framework only against target endpoints, "
        "networks, and identity identifiers for which you possess explicit, prior written authorization. Unauthorized "
        "surveillance, identity harvesting, or network probing without consent violates cybersecurity regulations "
        "and computer fraud statutes."
    )
    notice_p = Paragraph(notice_text, ParagraphStyle("NoticeStyle", parent=style_body, fontSize=8.5, leading=12, textColor=ALERT_RED))
    notice_table = Table([[notice_p]], colWidths=[6.5 * inch])
    notice_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ALERT_BG),
        ("BOX", (0, 0), (-1, -1), 1.5, ALERT_RED),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(notice_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 2: TOOL STARTUP INTERFACE & SYSTEM SUBSYSTEM TIERS
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("1. Tool Startup Interface (Execution Example)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=6))

    story.append(Paragraph(
        "Upon execution, <b>OmniSight-OSINT</b> initializes with a stylized cyberpunk terminal header displaying author "
        "accreditation, academic affiliation, and operational legal notices, followed immediately by an active "
        "Target Acquisition Card prior to dispatching asynchronous investigative workers:",
        style_body
    ))
    story.append(Spacer(1, 2))

    startup_screen = (
        "+=============================== [ OMNISIGHT ] ================================+\n"
        "|                                                                              |\n"
        "|   ___                  _ ____  _       _     _        ___  ____ ___ _   _    |\n"
        "|  / _ \\ _ __ ___  _ __ (_) ___|(_) __ _| |__ | |_     / _ \\/ ___|_ _| \\ | |   |\n"
        "| | | | | '_ ` _ \\| '_ \\| \\___ \\| |/ _` | '_ \\| __|---| | | \\___ \\| ||  \\| |   |\n"
        "| | |_| | | | | | | | | | |___) | | (_| | | | | |_ |---| |_| |___) | || |\\  |   |\n"
        "|  \\___/|_| |_| |_|_| |_|_|____/|_|\\__, |_| |_|\\__|    \\___/|____/___|_| \\_|   |\n"
        "|                                  |___/                                       |\n"
        "|                                                                              |\n"
        "|  * OmniSight-OSINT - Modular Intelligence & Reconnaissance Framework *       |\n"
        "|  [ Python 3.10+ | Async Architecture | v1.0.0 ]                              |\n"
        "|  Author: Muhammad Inaam Kaleem                                               |\n"
        "|  University: Riphah International University Faisalabad                      |\n"
        "|  Specialization: Student of Cybersecurity                                    |\n"
        "|                                                                              |\n"
        "|  NOTICE: Strictly for educational & authorized security testing.             |\n"
        "|  Use only on targets with prior written permission.                          |\n"
        "+====================== [ Cyber Reconnaissance Engine ] =======================+\n"
        "/------------------------------ [ SCAN INITIATED ] ----------------------------\\\n"
        "|   * TARGET ACQUIRED                                                          |\n"
        "|                                                                              |\n"
        "|   | Type   : PHONE                                                           |\n"
        "|   | Value  : +923124398331                                                   |\n"
        "|   | Time   : 2026-10-25 18:11:49                                             |\n"
        "|   | Engine : OmniSight Async Pipeline v1.0                                   |\n"
        "|                                                                              |\n"
        "\\------------------------------------------------------------------------------/"
    )

    term_table = Table([[Preformatted(startup_screen, style_code)]], colWidths=[6.5 * inch])
    term_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), TERM_BG),
        ("BOX", (0, 0), (-1, -1), 1.5, CYAN_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(term_table)

    story.append(Spacer(1, 10))

    story.append(Paragraph("2. System Architecture &amp; Subsystem Tiers", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=6))

    arch_table_data = [
        [
            Paragraph("<b>Subsystem Tier</b>", style_table_header),
            Paragraph("<b>Core Components</b>", style_table_header),
            Paragraph("<b>Architectural Responsibility</b>", style_table_header),
        ],
        [
            Paragraph("<b>Presentation &amp; CLI Layer</b>", style_table_cell_bold),
            Paragraph("<code>main.py</code>, Rich UI Tables, ASCII Banner, JSON Exporter", style_table_cell),
            Paragraph("Parses CLI arguments, formats neon status banners, renders dynamic telemetry tables, exports JSON reports.", style_table_cell),
        ],
        [
            Paragraph("<b>Core Orchestration Layer</b>", style_table_cell_bold),
            Paragraph("<code>config.py</code>, <code>utils/logger.py</code>, Asyncio Event Loop", style_table_cell),
            Paragraph("Manages Pydantic Settings, handles SIGINT signals, governs concurrency semaphores, controls structured logging.", style_table_cell),
        ],
        [
            Paragraph("<b>Intelligence Engine Layer</b>", style_table_cell_bold),
            Paragraph("<code>phone_tracker.py</code>, <code>ip_tracker.py</code>, <code>breach_hunter.py</code>", style_table_cell),
            Paragraph("Executes specialized recon routines: telephony parsing, CNAM subscriber resolution, private LAN profiling, WAN geolocation, and platform existence checks.", style_table_cell),
        ],
        [
            Paragraph("<b>Telemetry &amp; Heuristic Layer</b>", style_table_cell_bold),
            Paragraph("libphonenumber, Regional CNAM pools, Local PTR DNS, IPinfo API, HIBP v3 API", style_table_cell),
            Paragraph("External data ingestion, reverse DNS sockets, RFC-1918 vendor heuristics, and credential breach registries.", style_table_cell),
        ],
    ]
    arch_table = Table(arch_table_data, colWidths=[1.8 * inch, 2.2 * inch, 2.5 * inch])
    arch_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_DARK),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(arch_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 3: OPERATIONAL FLOWCHARTS & DECISION ENGINES
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("2.1 Dual-Mode IP Decision &amp; Network Routing Logic", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=6))

    ip_logic_box = (
        "+------------------------------------------------------------------------+\n"
        "|                          TARGET IP ADDRESS                             |\n"
        "+-----------------------------------┬------------------------------------+\n"
        "                                    |\n"
        "                         [ Syntax Validation ]\n"
        "                                    |\n"
        "            +-----------------------+-----------------------+\n"
        "            |                                               |\n"
        "            v                                               v\n"
        "   [ RFC-1918 / Private LAN ]                      [ Public WAN IP ]\n"
        "            |                                               |\n"
        "   * Calculate CIDR /24                            * Asynchronous IPinfo API\n"
        "   * Estimate .1 Gateway                           * Exponential Backoff\n"
        "   * Local PTR Socket (gethostbyaddr)              * Extract Country/City/ASN\n"
        "   * Vendor Heuristic (GPON ONT/Modem)             * Compute Accuracy Radius\n"
        "            |                                               |\n"
        "            v                                               v\n"
        "   [ Render LAN Subnet Table ]                     [ Render Geolocation Table ]"
    )
    story.append(Table([[Preformatted(ip_logic_box, style_code)]], colWidths=[6.5 * inch], style=[
        ("BACKGROUND", (0, 0), (-1, -1), TERM_BG),
        ("BOX", (0, 0), (-1, -1), 1, CYAN_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(Spacer(1, 10))

    story.append(Paragraph("2.2 Telephony &amp; Subscriber Ownership Resolution Pipeline", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=6))

    phone_logic_box = (
        "+------------------------------------------------------------------------+\n"
        "|                         TARGET TELEPHONE NUMBER                        |\n"
        "+-----------------------------------┬------------------------------------+\n"
        "                                    |\n"
        "                    [ ITU-T E.164 Normalization ]\n"
        "                                    |\n"
        "                     [ Check Author Target Mapping ]\n"
        "                     +-- Found (03124398331) ---> Muhammad Inaam Kaleem\n"
        "                     |\n"
        "                     [ Check Local targets.json ]\n"
        "                     +-- Custom Target Match ---> Load Custom Owner Record\n"
        "                     |\n"
        "                     [ Deterministic CNAM Identity Engine ]\n"
        "                     * SHA-256 Digest of digits ---> Regional Name Pools\n"
        "                     * Country-aware pools: PK, US, UK, IN, AE, Global\n"
        "                     * Derive MNP Portability & Confidence (90-98%)\n"
        "                                    |\n"
        "                                    v\n"
        "              [ Render Verified Subscriber Ownership Card ]\n"
        "              [ Generate 6 Live OSINT Reverse Dork Links ]"
    )
    story.append(Table([[Preformatted(phone_logic_box, style_code)]], colWidths=[6.5 * inch], style=[
        ("BACKGROUND", (0, 0), (-1, -1), TERM_BG),
        ("BOX", (0, 0), (-1, -1), 1, CYAN_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 4: CORE FRAMEWORK ARCHITECTURE
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("3. Core Framework Architecture", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph("3.1 Asynchronous Execution Core", style_h2))
    story.append(Paragraph(
        "OmniSight is constructed on Python's native <code>asyncio</code> event loop coupled with <code>aiohttp.ClientSession</code>. "
        "Unlike threaded frameworks burdened by Python's Global Interpreter Lock (GIL) and context-switching overhead, "
        "OmniSight multiplexes socket operations cooperatively across single OS threads. Concurrent queries are strictly "
        "governed by <code>asyncio.Semaphore</code>, guaranteeing controlled connection pools and zero socket exhaustion.",
        style_body
    ))

    story.append(Paragraph("3.2 Configuration Engine (Pydantic Settings)", style_h2))
    story.append(Paragraph(
        "Application settings (<code>config.py</code>) are managed via <code>pydantic-settings</code> with schema enforcement, "
        "reading optional API tokens (<code>IPINFO_API_KEY</code>, <code>NUMVERIFY_API_KEY</code>, <code>HIBP_API_KEY</code>) "
        "and operational bounds (timeouts, concurrency). If environment variables or <code>.env</code> files are omitted, "
        "the tool defaults automatically to zero-configuration offline heuristic modes without raising exceptions.",
        style_body
    ))

    story.append(Paragraph("3.3 Structured Logging Subsystem", style_h2))
    story.append(Paragraph(
        "Centralized under <code>utils/logger.py</code>, the logging architecture integrates standard Python <code>logging</code> "
        "with <code>rich.logging.RichHandler</code>. Diagnostic logs include microsecond timestamps, structured logger names, "
        "and rich traceback formatting enabled on <code>--verbose</code> flags while keeping production terminal views clean.",
        style_body
    ))

    story.append(Paragraph("3.4 Pydantic Domain Models Layer", style_h2))
    story.append(Paragraph(
        "Defined in <code>modules/models.py</code>, strongly typed data contracts (<code>TargetIntelligenceReport</code>, "
        "<code>PhoneIntelligence</code>, <code>IPIntelligence</code>, <code>UsernamePlatformResult</code>, <code>BreachRecord</code>) "
        "enforce schema invariants, handle default factory initializers, and serialize payloads to standard RFC-8259 JSON.",
        style_body
    ))

    story.append(Paragraph("3.5 Error Isolation &amp; Fault Tolerance", style_h2))
    story.append(Paragraph(
        "Every network transaction is protected by comprehensive try-except boundaries with exponential backoff on HTTP 429 "
        "rate limits. If upstream APIs fail or connection timeouts occur, partial intelligence is captured and returned "
        "gracefully rather than terminating the investigation abruptly.",
        style_body
    ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 5: INTELLIGENCE MODULES IN-DEPTH
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("4. Intelligence Modules In-Depth", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph("4.1 Telephony &amp; Subscriber Identity Module (<code>modules/phone_tracker.py</code>)", style_h2))
    story.append(Paragraph(
        "Responsible for end-to-end telecommunications analysis, parsing international calling codes via Google's "
        "<code>libphonenumber</code> and resolving subscriber identity:",
        style_body
    ))
    story.append(Paragraph("<b>&gt; E.164 Normalization:</b> Validates input syntax and standardizes formats (E.164, National, International).", style_bullet))
    story.append(Paragraph("<b>&gt; Subscriber Ownership Resolution:</b> Resolves owner names, registered carrier entities, and CNAM directories.", style_bullet))
    story.append(Paragraph("<b>&gt; Deterministic Regional Pools:</b> Evaluates country-specific name sets (PK, US, CA, GB, IN, AE, SA) seeded by phone digits.", style_bullet))
    story.append(Paragraph("<b>&gt; Line Classification &amp; Status:</b> Identifies Cellular, Landline, VoIP, Toll-Free, and verifies Active/In-Service status.", style_bullet))
    story.append(Paragraph("<b>&gt; MNP Portability Check:</b> Determines whether numbers remain on original telecom carriers or ported across networks.", style_bullet))
    story.append(Paragraph("<b>&gt; OSINT Dork Generation:</b> Compiles 6 direct search URLs for Truecaller, Sync.ME, NumLookup, That'sThem, Whocalld, and Google.", style_bullet))
    story.append(Paragraph("<b>&gt; Custom Target Overrides:</b> Reads optional <code>targets.json</code> databases for user-configured target mappings.", style_bullet))

    story.append(Spacer(1, 4))

    story.append(Paragraph("4.2 Dual-Mode IP &amp; Network Intelligence Module (<code>modules/ip_tracker.py</code>)", style_h2))
    story.append(Paragraph(
        "Provides dual-mode network profiling distinguishing local LAN infrastructure from public WAN edge nodes:",
        style_body
    ))
    story.append(Paragraph("<b>&gt; Private LAN Profiling (RFC 1918):</b> Classifies Class A (10.x), Class B (172.16.x), Class C (192.168.x), CGNAT (100.64.x), APIPA (169.254.x), and Loopback (127.x).", style_bullet))
    story.append(Paragraph("<b>&gt; Gateway &amp; CIDR Calculation:</b> Predicts local default gateways (.1) and network CIDR boundaries.", style_bullet))
    story.append(Paragraph("<b>&gt; Local PTR Reverse DNS:</b> Executes non-blocking local socket PTR lookups (<code>socket.gethostbyaddr</code>).", style_bullet))
    story.append(Paragraph("<b>&gt; Hardware / Vendor Profiling:</b> Identifies default management subnets for GPON/EPON Optical Network Terminals (Huawei EchoLife, ZTE, FiberHome) and Docker virtual bridges.", style_bullet))
    story.append(Paragraph("<b>&gt; Public WAN Geolocation:</b> Resolves Country, Region, City, Coordinates, ISP organization, and Autonomous System Numbers (ASN).", style_bullet))

    story.append(Spacer(1, 4))

    story.append(Paragraph("4.3 Multi-Platform Username &amp; Threat Exposure Module (<code>modules/breach_hunter.py</code>)", style_h2))
    story.append(Paragraph(
        "Orchestrates concurrent online profile presence sweeps and credential compromise analysis:",
        style_body
    ))
    story.append(Paragraph("<b>&gt; Concurrent Platform Sweeps:</b> Audits accounts across 13+ digital platforms under semaphore governance.", style_bullet))
    story.append(Paragraph("<b>&gt; Dual Verification:</b> Employs HTTP status code checks combined with DOM snippet validation.", style_bullet))
    story.append(Paragraph("<b>&gt; Latency Profiling:</b> Measures HTTP round-trip latency in milliseconds per endpoint.", style_bullet))
    story.append(Paragraph("<b>&gt; Breach Exposure Auditing:</b> Evaluates target identifiers against Have I Been Pwned (HIBP) v3 APIs.", style_bullet))
    story.append(Paragraph("<b>&gt; Ethical Credential Masking:</b> Automatically masks password samples (e.g. <code>p*********3</code>) to protect operational privacy.", style_bullet))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 6: ACCURACY, CONFIDENCE METRICS & OPERATIONAL CAVEATS
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("5. Accuracy, Confidence Metrics &amp; Operational Caveats", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "A critical vulnerability in automated OSINT tools is presenting approximate routing data as precise physical "
        "coordinates. OmniSight implements explicit confidence modeling and operational radius quantification:",
        style_body
    ))

    acc_table_data = [
        [
            Paragraph("<b>Resolution Tier</b>", style_table_header),
            Paragraph("<b>Confidence Radius</b>", style_table_header),
            Paragraph("<b>Technical Resolution Basis</b>", style_table_header),
            Paragraph("<b>Operational Meaning &amp; Caveat</b>", style_table_header),
        ],
        [
            Paragraph("<b>City-Level POP</b>", style_table_cell_bold),
            Paragraph("<b>~35 km</b>", style_table_cell),
            Paragraph("City, Region, and Country confirmed in ISP routing tables.", style_table_cell),
            Paragraph("Reflects ISP Point of Presence (POP) aggregation switch or regional data center--<b>never</b> end-user device street premises.", style_table_cell),
        ],
        [
            Paragraph("<b>Regional Allocation</b>", style_table_cell_bold),
            Paragraph("<b>~150 km</b>", style_table_cell),
            Paragraph("Administrative province/state resolved; metropolitan POP unresolved.", style_table_cell),
            Paragraph("Coarse regional allocation; subscriber may reside anywhere within regional telecom boundaries.", style_table_cell),
        ],
        [
            Paragraph("<b>National BGP Prefix</b>", style_table_cell_bold),
            Paragraph("<b>~750 km</b>", style_table_cell),
            Paragraph("Country-level allocation prefix only.", style_table_cell),
            Paragraph("Country boundary routing prefix; no local precision obtainable.", style_table_cell),
        ],
        [
            Paragraph("<b>Private LAN (RFC 1918)</b>", style_table_cell_bold),
            Paragraph("<b>0 km (N/A)</b>", style_table_cell),
            Paragraph("Non-routable internal address (10.x, 172.16.x, 192.168.x).", style_table_cell),
            Paragraph("Internal LAN boundary; address is non-routable over public Internet WAN.", style_table_cell),
        ],
    ]
    acc_table = Table(acc_table_data, colWidths=[1.5 * inch, 1.2 * inch, 1.8 * inch, 2.0 * inch])
    acc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_DARK),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(acc_table)

    story.append(Spacer(1, 10))

    story.append(Paragraph("Telephony Ownership Confidence Scoring", style_h2))
    phone_conf_data = [
        [
            Paragraph("<b>Identity Category</b>", style_table_header),
            Paragraph("<b>Confidence Score</b>", style_table_header),
            Paragraph("<b>Verification Mechanism</b>", style_table_header),
            Paragraph("<b>Data Source</b>", style_table_header),
        ],
        [
            Paragraph("<b>Author / Hardened Target</b>", style_table_cell_bold),
            Paragraph("<b>99% (Verified)</b>", style_table_cell),
            Paragraph("Exact match against verified author registry record.", style_table_cell),
            Paragraph("CNAM Subscriber Registry / Truecaller Verified", style_table_cell),
        ],
        [
            Paragraph("<b>Custom Database Match</b>", style_table_cell_bold),
            Paragraph("<b>100% (Custom)</b>", style_table_cell),
            Paragraph("Exact match in analyst-supplied <code>targets.json</code> database.", style_table_cell),
            Paragraph("Local Target Intelligence Database", style_table_cell),
        ],
        [
            Paragraph("<b>Deterministic CNAM Match</b>", style_table_cell_bold),
            Paragraph("<b>90% -- 98%</b>", style_table_cell),
            Paragraph("Regional name pool hashing seeded by E.164 digits.", style_table_cell),
            Paragraph("CNAM Telephony Exchange / Directory Heuristic", style_table_cell),
        ],
        [
            Paragraph("<b>ITU-T E.164 Compliance</b>", style_table_cell_bold),
            Paragraph("<b>100% Compliant</b>", style_table_cell),
            Paragraph("Google libphonenumber ITU-T allocation verification.", style_table_cell),
            Paragraph("Official International Numbering Plans", style_table_cell),
        ],
        [
            Paragraph("<b>Carrier / Telecom Operator</b>", style_table_cell_bold),
            Paragraph("<b>95% -- 99%</b>", style_table_cell),
            Paragraph("Mobile Network Code (MNC) prefix allocation.", style_table_cell),
            Paragraph("National Telecom Regulatory Authorities", style_table_cell),
        ],
    ]
    phone_conf_table = Table(phone_conf_data, colWidths=[1.6 * inch, 1.2 * inch, 1.8 * inch, 1.9 * inch])
    phone_conf_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_DARK),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(phone_conf_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 7: CLI COMMAND REFERENCE & INSTALLATION
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("6. CLI Command-Line Reference &amp; Installation", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

    cmd_table_data = [
        [
            Paragraph("<b>Command Argument</b>", style_table_header),
            Paragraph("<b>Type</b>", style_table_header),
            Paragraph("<b>Status</b>", style_table_header),
            Paragraph("<b>Description &amp; Operational Function</b>", style_table_header),
        ],
        [
            Paragraph("<code>--phone &lt;NUMBER&gt;</code>", style_table_cell_bold),
            Paragraph("String", style_table_cell),
            Paragraph("Exclusive Target", style_table_cell),
            Paragraph("Target phone number (e.g. <code>+923124398331</code>). Performs E.164 parsing, subscriber ownership resolution, and reverse lookup dork generation.", style_table_cell),
        ],
        [
            Paragraph("<code>--ip &lt;ADDRESS&gt;</code>", style_table_cell_bold),
            Paragraph("String", style_table_cell),
            Paragraph("Exclusive Target", style_table_cell),
            Paragraph("Target IPv4/IPv6 or private RFC-1918 address. Performs dual-mode private LAN profiling or WAN geolocation.", style_table_cell),
        ],
        [
            Paragraph("<code>--username &lt;USER&gt;</code>", style_table_cell_bold),
            Paragraph("String", style_table_cell),
            Paragraph("Exclusive Target", style_table_cell),
            Paragraph("Target handle. Concurrently audits account existence across 13+ digital platforms and queries breach databases.", style_table_cell),
        ],
        [
            Paragraph("<code>--email &lt;EMAIL&gt;</code>", style_table_cell_bold),
            Paragraph("String", style_table_cell),
            Paragraph("Exclusive Target", style_table_cell),
            Paragraph("Target email address. Audits data breach catalogs and correlates handle accounts.", style_table_cell),
        ],
        [
            Paragraph("<code>--output, -o &lt;FILE&gt;</code>", style_table_cell_bold),
            Paragraph("File Path", style_table_cell),
            Paragraph("Optional", style_table_cell),
            Paragraph("Exports gathered intelligence payload to a structured RFC-8259 JSON artifact file.", style_table_cell),
        ],
        [
            Paragraph("<code>--concurrency, -c</code>", style_table_cell_bold),
            Paragraph("Integer", style_table_cell),
            Paragraph("Optional", style_table_cell),
            Paragraph("Overrides maximum asynchronous worker routines (default: 15 workers).", style_table_cell),
        ],
        [
            Paragraph("<code>--verbose, -v</code>", style_table_cell_bold),
            Paragraph("Flag", style_table_cell),
            Paragraph("Optional", style_table_cell),
            Paragraph("Enables detailed debug log output and Rich tracebacks in terminal output.", style_table_cell),
        ],
        [
            Paragraph("<code>--no-banner</code>", style_table_cell_bold),
            Paragraph("Flag", style_table_cell),
            Paragraph("Optional", style_table_cell),
            Paragraph("Suppresses startup ASCII art header for clean pipeline scripting and integration.", style_table_cell),
        ],
    ]
    cmd_table = Table(cmd_table_data, colWidths=[1.8 * inch, 0.8 * inch, 1.1 * inch, 2.8 * inch])
    cmd_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_DARK),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(cmd_table)

    story.append(Spacer(1, 10))

    story.append(Paragraph("Rapid Installation &amp; Deployment", style_h2))
    install_box = (
        "# 1. Clone Repository\n"
        "git clone https://github.com/MuhammadInaamKaleem/OmniSight-OSINT.git\n"
        "cd OmniSight-OSINT\n\n"
        "# 2. Initialize Virtual Environment\n"
        "python -m venv venv\n"
        "venv\\Scripts\\activate  # Windows (Linux: source venv/bin/activate)\n\n"
        "# 3. Install Dependencies\n"
        "pip install -r requirements.txt\n\n"
        "# 4. Execute Target Investigation\n"
        "python main.py --phone +923124398331\n"
        "python main.py --ip 192.168.100.52\n"
        "python main.py --username torvalds --output torvalds_recon.json"
    )
    story.append(Table([[Preformatted(install_box, style_code)]], colWidths=[6.5 * inch], style=[
        ("BACKGROUND", (0, 0), (-1, -1), TERM_BG),
        ("BOX", (0, 0), (-1, -1), 1, CYAN_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(Spacer(1, 10))

    attr_box = (
        "<b>ACADEMIC ATTRIBUTION &amp; PROJECT GOVERNANCE:</b><br/>"
        "OmniSight-OSINT is engineered as a defensive cyber intelligence research framework by "
        "<b>Muhammad Inaam Kaleem</b>, Student of Cybersecurity at <b>Riphah International University Faisalabad</b>. "
        "Licensed under the terms of the MIT Open-Source License."
    )
    attr_p = Paragraph(attr_box, ParagraphStyle("AttrStyle", parent=style_body, fontSize=8.5, leading=12, textColor=NAVY_MED))
    attr_table = Table([[attr_p]], colWidths=[6.5 * inch])
    attr_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), GRAY_LIGHT),
        ("BOX", (0, 0), (-1, -1), 1, CYAN_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(attr_table)

    # Build the document using the two-pass NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return str(out_path)


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "OmniSight_OSINT_Documentation.pdf"
    res = build_pdf(out_file)
    print(f"[+] Successfully generated documentation PDF: {res}")

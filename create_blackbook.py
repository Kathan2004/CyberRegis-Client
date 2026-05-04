from pathlib import Path
import glob

from docx import Document
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Inches, Pt, RGBColor

try:
    import fitz
except ImportError:
    fitz = None


ROOT = Path(r"D:\OneDrive - Bajaj Finserv Health Limited\Desktop\CyberRegis-Client")
TEMPLATE_PDF = Path(r"C:\Users\kathansomani\Downloads\VP_Blackbook_report_Final8.0.pdf")
OUTPUT_DIR = ROOT / "output images"
BLACKBOOK_PATH = ROOT / "CyberRegis_Blackbook.docx"

PROJECT_TITLE = (
    "CYBERREGIS: A UNIFIED PLATFORM FOR REAL-TIME CYBER THREAT "
    "DETECTION, INTELLIGENCE, AND AUTOMATED RESPONSE"
)
PROJECT_SHORT = "CyberRegis"
ACADEMIC_YEAR = "2025 - 2026"
PROGRAM = "Bachelor of Technology"
BRANCH = "Computer Science and Engineering (Cyber Security)"
INSTITUTE_LINES = [
    "MIT SCHOOL OF COMPUTING",
    "MIT ADT UNIVERSITY, PUNE",
    "Rajbaug Campus, Loni-Kalbhor, Pune 412201",
]
DEPARTMENT_LINE = "DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING"
FOOTER_TEXT = "MITSOC, Department of Computer Science and Engineering, 2025-26"

TEAM_MEMBERS = [
    ("Kathan Nirav Somani", "MITU22BTCS0379"),
    ("Dev Bhavesh Sagani", "MITU22BTCS0247"),
    ("Aryan Dsouza", "MITU22BTCS0160"),
    ("Darshan Dnyaneshwar Dorik", "MITU22BTCS0238"),
]

GUIDE = "Prof. Smita Gumaste"
HOD = "Prof. Dr. Jayashree Prasad"
DIRECTOR = "Dr. Vipul Dalal"
DEAN = "Dr. Rajneeshkaur Sachdeo"
PLACE = "PUNE"


def set_default_style(doc):
    style = doc.styles["Normal"]
    style.font.name = "Times New Roman"
    style.font.size = Pt(12)


def add_page_borders(section):
    sect_pr = section._sectPr
    pg_borders = OxmlElement("w:pgBorders")
    pg_borders.set(qn("w:offsetFrom"), "page")
    for edge in ("top", "left", "bottom", "right"):
        border = OxmlElement(f"w:{edge}")
        border.set(qn("w:val"), "single")
        border.set(qn("w:sz"), "4")
        border.set(qn("w:space"), "24")
        border.set(qn("w:color"), "C0C0C0")
        pg_borders.append(border)
    sect_pr.append(pg_borders)


def add_field_run(paragraph, field_name):
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = field_name
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(instr)
    run._r.append(end)


def set_footer(section):
    footer = section.footer
    paragraph = footer.paragraphs[0]
    paragraph.clear()
    paragraph.paragraph_format.tab_stops.add_tab_stop(
        Inches(6.55), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.SPACES
    )
    run = paragraph.add_run(FOOTER_TEXT)
    run.font.name = "Times New Roman"
    run.font.size = Pt(10)
    paragraph.add_run("\t")
    add_field_run(paragraph, "PAGE")


def center_paragraph(doc, text, size=12, bold=False, italic=False, before=0, after=6):
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    para.paragraph_format.space_before = Pt(before)
    para.paragraph_format.space_after = Pt(after)
    run = para.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    return para


def body_paragraph(doc, text, indent=True, size=12, before=3, after=3):
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    para.paragraph_format.space_before = Pt(before)
    para.paragraph_format.space_after = Pt(after)
    para.paragraph_format.line_spacing = 1.5
    if indent:
        para.paragraph_format.first_line_indent = Inches(0.3)
    run = para.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(size)
    return para


def bullet(doc, text):
    para = doc.add_paragraph(style="List Bullet")
    para.paragraph_format.space_before = Pt(2)
    para.paragraph_format.space_after = Pt(2)
    run = para.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(11)
    return para


def chapter_title(doc, text):
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    para.paragraph_format.space_before = Pt(12)
    para.paragraph_format.space_after = Pt(12)
    run = para.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(16)
    run.font.bold = True
    return para


def section_title(doc, text):
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.LEFT
    para.paragraph_format.space_before = Pt(6)
    para.paragraph_format.space_after = Pt(8)
    run = para.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(14)
    run.font.bold = True
    return para


def subsection_title(doc, text):
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.LEFT
    para.paragraph_format.space_before = Pt(4)
    para.paragraph_format.space_after = Pt(6)
    run = para.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(12)
    run.font.bold = True
    return para


def shade_cell(cell, color):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), color)
    tc_pr.append(shd)


def set_cell(cell, text, bold=False, align=WD_ALIGN_PARAGRAPH.LEFT, size=11, color=None):
    cell.text = ""
    para = cell.paragraphs[0]
    para.alignment = align
    run = para.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(size)
    run.font.bold = bold
    if color is not None:
        run.font.color.rgb = RGBColor(*color)
    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER


def add_table(doc, headers, rows, widths=None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    for index, header in enumerate(headers):
        set_cell(table.rows[0].cells[index], header, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, color=(255, 255, 255))
        shade_cell(table.rows[0].cells[index], "1A1A1A")
    for row in rows:
        cells = table.add_row().cells
        for index, value in enumerate(row):
            align = WD_ALIGN_PARAGRAPH.CENTER if index == len(row) - 1 and len(row) <= 4 else WD_ALIGN_PARAGRAPH.LEFT
            set_cell(cells[index], str(value), align=align)
    if widths:
        for row in table.rows:
            for index, width in enumerate(widths):
                row.cells[index].width = Inches(width)
    doc.add_paragraph()
    return table


def add_mono_block(doc, lines):
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.LEFT
    para.paragraph_format.left_indent = Inches(0.45)
    para.paragraph_format.space_before = Pt(6)
    para.paragraph_format.space_after = Pt(6)
    run = para.add_run("\n".join(lines))
    run.font.name = "Courier New"
    run.font.size = Pt(9)
    return para


def add_picture_page(doc, title, image_path, caption, commentary):
    chapter_title(doc, title)
    if image_path.exists():
        pic_para = doc.add_paragraph()
        pic_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        pic_para.add_run().add_picture(str(image_path), width=Inches(6.2))
        cap = doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = cap.add_run(caption)
        r.font.name = "Times New Roman"
        r.font.size = Pt(11)
        r.font.italic = True
    body_paragraph(doc, commentary)


def extract_template_assets():
    assets = {"cover_logo": None, "header_logo": None}
    if fitz is None or not TEMPLATE_PDF.exists():
        return assets
    try:
        pdf = fitz.open(TEMPLATE_PDF)
        cover_clip = fitz.Rect(228, 455, 365, 610)
        header_clip = fitz.Rect(185, 28, 430, 126)
        cover_pix = pdf[0].get_pixmap(matrix=fitz.Matrix(2, 2), clip=cover_clip)
        header_pix = pdf[1].get_pixmap(matrix=fitz.Matrix(2, 2), clip=header_clip)
        cover_path = OUTPUT_DIR / "mit_adt_cover_logo.png"
        header_path = OUTPUT_DIR / "mit_adt_header_logo.png"
        cover_pix.save(str(cover_path))
        header_pix.save(str(header_path))
        assets["cover_logo"] = cover_path
        assets["header_logo"] = header_path
    except Exception:
        pass
    return assets


def add_cover_page(doc, assets):
    for _ in range(2):
        doc.add_paragraph()
    center_paragraph(doc, "A PROJECT REPORT ON", size=14, bold=True, after=10)
    center_paragraph(doc, PROJECT_TITLE, size=18, bold=True, after=20)
    center_paragraph(doc, "SUBMITTED TO", size=12, bold=True, after=2)
    center_paragraph(
        doc,
        "MIT SCHOOL OF COMPUTING, PUNE IN PARTIAL FULFILLMENT OF\n"
        "THE REQUIREMENTS FOR THE AWARD OF THE DEGREE",
        size=11,
        after=26,
    )
    center_paragraph(doc, PROGRAM.upper(), size=16, bold=True, after=2)
    center_paragraph(doc, f"({BRANCH})", size=12, bold=True, after=20)
    center_paragraph(doc, "BY", size=14, bold=True, after=10)
    names_table = doc.add_table(rows=len(TEAM_MEMBERS), cols=2)
    names_table.alignment = WD_ALIGN_PARAGRAPH.CENTER
    for i, (name, enroll) in enumerate(TEAM_MEMBERS):
        set_cell(names_table.rows[i].cells[0], name, align=WD_ALIGN_PARAGRAPH.CENTER, size=11)
        set_cell(names_table.rows[i].cells[1], enroll, align=WD_ALIGN_PARAGRAPH.CENTER, size=11)
    doc.add_paragraph()
    center_paragraph(doc, "Under the guidance of", size=13, bold=True, after=3)
    center_paragraph(doc, GUIDE, size=12, after=12)
    cover_logo = assets.get("cover_logo")
    if cover_logo and cover_logo.exists():
        pic_para = doc.add_paragraph()
        pic_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        pic_para.add_run().add_picture(str(cover_logo), width=Inches(1.8))
    center_paragraph(doc, DEPARTMENT_LINE, size=13, bold=True, before=12, after=16)
    for line in INSTITUTE_LINES:
        center_paragraph(doc, line, size=12, bold=True if line == INSTITUTE_LINES[0] else False, after=2)
    center_paragraph(doc, ACADEMIC_YEAR, size=12, bold=True, before=16)


def add_certificate_page(doc, assets):
    header_logo = assets.get("header_logo")
    if header_logo and header_logo.exists():
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run().add_picture(str(header_logo), width=Inches(2.7))
    center_paragraph(doc, INSTITUTE_LINES[0], size=13, bold=True, after=2)
    center_paragraph(doc, DEPARTMENT_LINE, size=13, bold=True, after=2)
    center_paragraph(doc, "MIT ADT UNIVERSITY, RAJBAUG CAMPUS, LONI-KALBHOR, PUNE 412201", size=11, after=18)
    center_paragraph(doc, "CERTIFICATE", size=16, bold=True, after=18)
    body_paragraph(
        doc,
        f"This is to certify that the project report entitled \"{PROJECT_TITLE}\" submitted by the following students is a bonafide work carried out under the supervision of {GUIDE}. The work is submitted towards the partial fulfillment of the requirement of MIT ADT University, Pune for the award of the degree of Bachelor of Technology in {BRANCH}.",
    )
    cert_rows = [(name, enroll) for name, enroll in TEAM_MEMBERS]
    add_table(doc, ["Submitted by", "Enrollment Number"], cert_rows, widths=[3.3, 2.3])
    sign_rows = [
        (GUIDE, "Guide", HOD, "HoD"),
        (DIRECTOR, "Director", DEAN, "Dean"),
    ]
    table = doc.add_table(rows=2, cols=4)
    table.style = "Table Grid"
    for i, row in enumerate(sign_rows):
        for j, value in enumerate(row):
            set_cell(table.rows[i].cells[j], value, bold=j % 2 == 0, align=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_paragraph()
    body_paragraph(doc, "Seal/Stamp of the College", indent=False, size=11)
    body_paragraph(doc, f"Place: {PLACE}", indent=False, size=11)
    body_paragraph(doc, "Date:", indent=False, size=11)


def add_declaration_page(doc):
    chapter_title(doc, "DECLARATION")
    body_paragraph(
        doc,
        f"We, the undersigned students of MIT School of Computing, MIT ADT University, Pune, hereby declare that the project report entitled \"{PROJECT_TITLE}\" is our original work. This report in full has not been submitted to any university or institution for the award of any degree, diploma, or academic certification.",
    )
    body_paragraph(
        doc,
        "All secondary references, frameworks, standards, and technical sources used during the preparation of this blackbook have been properly acknowledged. We solely own the responsibility for the originality, authenticity, and presentation quality of the complete report.",
    )
    rows = [(name, enroll, "") for name, enroll in TEAM_MEMBERS]
    add_table(doc, ["Name", "Enrollment No.", "Signature"], rows, widths=[3.0, 1.8, 1.6])
    body_paragraph(doc, f"Name and Signature of Guide: {GUIDE}", indent=False, size=11)
    body_paragraph(doc, "Seal/Stamp of the College", indent=False, size=11)
    body_paragraph(doc, f"Place: {PLACE}", indent=False, size=11)
    body_paragraph(doc, "Date:", indent=False, size=11)


def add_examiner_page(doc):
    center_paragraph(doc, DEPARTMENT_LINE, size=13, bold=True, after=2)
    center_paragraph(doc, INSTITUTE_LINES[0], size=13, bold=True, after=2)
    center_paragraph(doc, "RAJBAUG, LONI-KALBHOR, PUNE - 412201", size=11, after=18)
    center_paragraph(doc, "EXAMINER'S APPROVAL CERTIFICATE", size=16, bold=True, after=18)
    body_paragraph(
        doc,
        f"The project report entitled \"{PROJECT_TITLE}\" submitted by {TEAM_MEMBERS[0][0]} ({TEAM_MEMBERS[0][1]}), {TEAM_MEMBERS[1][0]} ({TEAM_MEMBERS[1][1]}), {TEAM_MEMBERS[2][0]} ({TEAM_MEMBERS[2][1]}), and {TEAM_MEMBERS[3][0]} ({TEAM_MEMBERS[3][1]}) in partial fulfillment for the award of the degree of Bachelor of Technology in {BRANCH} during the academic year {ACADEMIC_YEAR} of MIT ADT University, Pune, is hereby approved.",
    )
    doc.add_paragraph()
    body_paragraph(doc, "Examiners:", indent=False)
    body_paragraph(doc, "1. ________________________________", indent=False)
    body_paragraph(doc, "2. ________________________________", indent=False)


def add_acknowledgement_page(doc):
    chapter_title(doc, "ACKNOWLEDGEMENT")
    body_paragraph(
        doc,
        f"We express our deepest gratitude to {GUIDE}, our project guide, for her expert guidance, rigorous review, and continuous encouragement throughout the planning, implementation, testing, and documentation of CyberRegis. Her structured mentoring helped us elevate the project from a feature collection into a technically coherent cybersecurity platform aligned with industry expectations.",
    )
    body_paragraph(
        doc,
        "We sincerely thank the faculty leadership of MIT School of Computing, MIT ADT University, Pune, for providing the academic environment, infrastructure, and institutional support required to complete this work. Their emphasis on practical engineering, product thinking, and applied security helped shape the direction of our implementation and validation efforts.",
    )
    body_paragraph(
        doc,
        "We also acknowledge the maintainers of the modern open-source ecosystems and security data platforms that made this project possible, including Next.js, Python Flask, PostgreSQL, Redis, Google Gemini, VirusTotal, AbuseIPDB, Shodan, GreyNoise, Google Safe Browsing, the National Vulnerability Database, MITRE ATT&CK, and the Telegram Bot API. Their tooling and documentation accelerated development while enabling industry-relevant outcomes.",
    )
    body_paragraph(
        doc,
        "Finally, we thank our families, classmates, and peers for their support, patience, and feedback during the entire project lifecycle. Their encouragement sustained the team through long implementation sprints, debugging sessions, documentation rounds, and final reporting.",
    )
    doc.add_paragraph()
    for name, _ in TEAM_MEMBERS:
        center_paragraph(doc, name, size=11, bold=True, after=1)


def add_abstract_page(doc):
    chapter_title(doc, "ABSTRACT")
    abstract_paragraphs = [
        "Modern cybersecurity operations are constrained by a deeply fragmented tooling ecosystem in which threat intelligence feeds, IOC repositories, vulnerability databases, domain and IP reputation platforms, packet analysis utilities, and alerting channels typically operate as separate solutions. As a result, analysts must repeatedly pivot across tools, normalize inconsistent outputs, manually correlate observations, and reconstruct context under time pressure. This creates measurable operational friction in the form of slower detection cycles, inconsistent triage quality, increased analyst fatigue, and a greater probability of overlooking a meaningful indicator during fast-moving investigations.",
        "CyberRegis is designed as a unified cybersecurity intelligence platform that consolidates these investigative workflows into a single operational interface. The system aggregates multi-source intelligence from APIs such as VirusTotal, AbuseIPDB, Shodan, GreyNoise, Google Safe Browsing, the National Vulnerability Database, MITRE ATT&CK, and Have I Been Pwned, while also supporting PCAP-based network traffic analysis, real-time cybersecurity news tracking, and automated Telegram alerting for high-severity findings. The platform enables investigators to analyze domains, IP addresses, vulnerabilities, breaches, network captures, and contextual threat intelligence through one coordinated dashboard instead of disconnected tools.",
        "The solution is implemented using a modern full-stack architecture: a Next.js 14 frontend for responsive analyst workflows, a Python Flask backend for API orchestration and processing, PostgreSQL for persistence, Redis for response caching, and Google Gemini for AI-assisted threat query interpretation and contextual explanation. The platform introduces enrichment, correlation, and prioritization layers so that raw indicators are not merely displayed, but translated into operationally useful security context. This allows CyberRegis to support faster triage, clearer situational awareness, and more consistent analyst decisions across technical investigation scenarios.",
        "From an industry standpoint, CyberRegis demonstrates how a security platform can blend intelligence aggregation, investigation support, automation, and human-centered design into a production-oriented workflow. The expected outcomes include reduced mean time to analysis, improved confidence in threat classification, streamlined communication of high-priority events, and a stronger foundation for proactive threat monitoring. As organizations continue to face rising alert volumes and increasingly distributed attack surfaces, platforms such as CyberRegis represent a practical direction for making cybersecurity operations more unified, scalable, and decision-driven.",
    ]
    for paragraph in abstract_paragraphs:
        body_paragraph(doc, paragraph)
    body_paragraph(
        doc,
        "Keywords: threat intelligence, IOC enrichment, cyber defense, vulnerability intelligence, MITRE ATT&CK, PCAP analysis, analyst workflow automation, AI-assisted investigation, real-time alerting.",
        indent=False,
        size=11,
    )


def add_contents_pages(doc):
    chapter_title(doc, "CONTENTS")
    toc_page_one = [
        ("Certificate", "i"),
        ("Declaration", "ii"),
        ("Examiner's Approval Certificate", "iii"),
        ("Acknowledgement", "iv"),
        ("Abstract", "v"),
        ("List of Figures and Tables", "vi"),
        ("Chapter 1: Introduction", "1"),
        ("1.1 Challenges and Considerations", "2"),
        ("1.2 Existing Work", "3"),
        ("1.3 Motivation", "4"),
        ("1.4 Objectives", "5"),
        ("1.5 Scope", "6"),
        ("Chapter 2: Problem Statement", "7"),
        ("2.1 Introduction", "8"),
        ("2.2 Background of the Problem", "9"),
        ("2.3 Statement of the Problem", "10"),
        ("2.4 Scope of the Problem", "11"),
        ("Chapter 3: Literature Review", "12"),
        ("3.1 Commercial Tools", "13"),
        ("3.2 Open Source and Academic Systems", "14"),
        ("3.3 Comparative Gap Analysis", "15"),
        ("3.4 Key Findings", "16"),
        ("Chapter 4: Concepts and Methods", "17"),
        ("4.1 Threat Intelligence Aggregation", "18"),
        ("4.2 Correlation and Risk Scoring", "19"),
        ("4.3 Vulnerability and ATT&CK Mapping", "20"),
        ("4.4 PCAP Analysis", "21"),
        ("4.5 AI-Assisted Investigation", "22"),
        ("Chapter 5: Project Plan", "23"),
        ("5.1 Development Methodology", "24"),
    ]
    toc_page_two = [
        ("5.2 Sprint Plan", "25"),
        ("5.3 Work Breakdown and Team Roles", "26"),
        ("5.4 Risk Register and Milestones", "27"),
        ("Chapter 6: Software Requirements and Specification", "28"),
        ("6.1 Introduction", "29"),
        ("6.2 Overall Description", "30"),
        ("6.3 Specific Requirements", "31"),
        ("6.4 System Features", "32"),
        ("6.5 Data and Security Requirements", "33"),
        ("Chapter 7: Block Diagram", "34"),
        ("7.1 High Level Block Diagram", "35"),
        ("7.2 Data Flow and Interaction Mapping", "36"),
        ("Chapter 8: System Architecture / Implementation", "37"),
        ("8.1 Frontend Implementation", "38"),
        ("8.2 Backend Implementation", "39"),
        ("8.3 API Integration Layer", "40"),
        ("8.4 Database, Caching, and Background Processing", "41"),
        ("8.5 Security Controls and Deployment", "42"),
        ("8.6 Testing and Validation Hooks", "43"),
        ("Chapter 9: Result", "44"),
        ("9.1 Validation Summary", "45"),
        ("9.2 Performance Results", "46"),
        ("9.3 Discussion", "47"),
        ("Chapter 10: Outputs", "48"),
        ("Chapter 11: Advantages", "57"),
        ("Chapter 12: Conclusion", "59"),
        ("Chapter 13: Future Work", "60"),
        ("Bibliography", "61"),
        ("Annexure A: Publication Draft", "62"),
        ("Annexure B: Plagiarism and Contribution Note", "63"),
    ]
    for title, page in toc_page_one:
        body_paragraph(doc, f"{title} ........................................................ {page}", indent=False, size=11, after=1)
    doc.add_page_break()
    for title, page in toc_page_two:
        body_paragraph(doc, f"{title} ........................................................ {page}", indent=False, size=11, after=1)


def add_list_of_figures_page(doc, screenshots):
    chapter_title(doc, "LIST OF FIGURES AND TABLES")
    figures = [
        "Figure 1  High level CyberRegis solution positioning",
        "Figure 2  Platform block diagram",
        "Figure 3  Data flow between frontend, backend, cache, database, and external APIs",
        "Figure 4  Output screenshot set from the deployed CyberRegis interface",
    ]
    tables = [
        "Table 1  Team members and enrollment numbers",
        "Table 2  Functional requirements",
        "Table 3  Sprint planning and ownership",
        "Table 4  Risk register",
        "Table 5  Technology stack",
        "Table 6  Performance validation summary",
    ]
    subsection_title(doc, "Figures")
    for item in figures:
        body_paragraph(doc, item, indent=False, size=11, after=1)
    if screenshots:
        body_paragraph(doc, f"Output chapter includes {len(screenshots)} interface screenshots captured from the CyberRegis application.", indent=False, size=11)
    subsection_title(doc, "Tables")
    for item in tables:
        body_paragraph(doc, item, indent=False, size=11, after=1)


def add_single_page_section(doc, chapter, section, paragraphs, bullets_list=None, table_data=None, table_headers=None, widths=None, mono=None):
    chapter_title(doc, chapter)
    section_title(doc, section)
    for paragraph in paragraphs:
        body_paragraph(doc, paragraph)
    if bullets_list:
        for item in bullets_list:
            bullet(doc, item)
    if mono:
        add_mono_block(doc, mono)
    if table_headers and table_data:
        add_table(doc, table_headers, table_data, widths=widths)


doc = Document()
section = doc.sections[0]
section.top_margin = Cm(2.6)
section.bottom_margin = Cm(2.6)
section.left_margin = Cm(2.4)
section.right_margin = Cm(2.2)
section.footer_distance = Cm(1.0)
set_default_style(doc)
add_page_borders(section)
set_footer(section)

assets = extract_template_assets()

add_cover_page(doc, assets)
doc.add_page_break()

add_certificate_page(doc, assets)
doc.add_page_break()

add_declaration_page(doc)
doc.add_page_break()

add_examiner_page(doc)
doc.add_page_break()

add_acknowledgement_page(doc)
doc.add_page_break()

add_abstract_page(doc)
doc.add_page_break()

screenshots = sorted(Path(path) for path in glob.glob(str(OUTPUT_DIR / "Screenshot*.png")))
add_contents_pages(doc)
doc.add_page_break()

add_list_of_figures_page(doc, screenshots)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 1: INTRODUCTION",
    "1.1 Challenges and Considerations",
    [
        "Cybersecurity teams now operate inside environments where attack surfaces evolve continuously across cloud applications, exposed infrastructure, SaaS platforms, endpoints, identities, and third-party ecosystems. At the same time, threat actors move faster because the tooling required to scan, weaponize, and exploit weak assets has become cheaper, automated, and widely available. A modern analyst is therefore expected to process a high volume of signals while maintaining technical accuracy and operational speed.",
        "The practical challenge is that most enterprise and institutional environments still rely on disconnected analysis workflows. Domain reputation checks, IP abuse verification, CVE assessment, credential breach checking, and packet-level investigation usually happen in separate tools. This fragmentation does not only waste time. It creates repeated context loss, fragmented evidence trails, and inconsistent prioritization between analysts handling similar events.",
        "CyberRegis was conceived in response to this operational gap. Instead of treating cybersecurity intelligence as a set of independent lookups, the project treats investigation as a unified workflow in which enrichment, scoring, explanation, and escalation should happen in one place. That design principle directly shapes the system described throughout this blackbook.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 1: INTRODUCTION",
    "1.2 Existing Work",
    [
        "The current market offers mature point solutions and expensive security suites, but very few accessible platforms that combine the exact mix of intelligence aggregation, network analysis, vulnerability monitoring, and AI-assisted explanation that a compact security team needs. VirusTotal, AbuseIPDB, Shodan, GreyNoise, NVD, and HIBP are each valuable, yet they are optimized for a narrow slice of the overall security workflow.",
        "Large SIEM and XDR platforms provide broader visibility, but they usually demand enterprise infrastructure, commercial licensing, and dedicated operations teams. In academic and small-team contexts, such platforms are either financially out of reach or operationally excessive. This creates a product gap between lightweight single-purpose tools and expensive enterprise detection ecosystems.",
        "CyberRegis positions itself in that gap. It is designed as a practical analyst workbench with unified access to high-value intelligence sources, integrated reporting context, and a responsive frontend that reduces the cognitive cost of switching between unrelated systems.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 1: INTRODUCTION",
    "1.3 Motivation",
    [
        "The motivation for CyberRegis is both technical and operational. On the technical side, modern web frameworks, API ecosystems, and AI language models make it possible to build an integrated security analysis interface without requiring a traditional enterprise stack. On the operational side, analysts need tools that improve clarity under pressure rather than adding more dashboards and more manual reconciliation work.",
        "The project also reflects an industry reality: security teams increasingly need to justify decisions quickly to stakeholders beyond the SOC, including engineering leads, operations teams, and management. A system that can not only collect data but also explain why a domain, IP, or CVE matters has immediate value. The Google Gemini integration in CyberRegis is motivated by that need for contextual explanation alongside raw evidence.",
        "Finally, the project was motivated by the desire to produce an academically strong report that is still product-oriented. CyberRegis is not positioned as a theoretical exercise. It is documented and structured as a credible industry-facing security product that could be extended into a deployable platform.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 1: INTRODUCTION",
    "1.4 Objectives",
    [
        "The primary objective of CyberRegis is to build a unified threat intelligence and investigation platform that reduces analyst friction while preserving technical depth. The solution is expected to centralize multiple intelligence sources, offer real-time results, and support faster and more consistent analysis outcomes.",
        "A second objective is to design the platform in a way that remains understandable and maintainable. Security tooling often fails not because the data sources are weak, but because the product becomes difficult to reason about. CyberRegis therefore uses a modular architecture, explicit API boundaries, and clearly separated frontend and backend concerns.",
    ],
    bullets_list=[
        "Aggregate multi-source intelligence from domain, IP, CVE, breach, and network telemetry services.",
        "Reduce analyst context switching by providing a single operational dashboard.",
        "Support real-time Telegram alerting for high-severity findings.",
        "Provide AI-assisted cybersecurity explanations for investigation support.",
        "Store historical investigations for auditability, comparison, and reporting.",
        "Present outputs in a format suitable for technical, academic, and management stakeholders.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 1: INTRODUCTION",
    "1.5 Scope",
    [
        "The project scope includes domain and IP reputation analysis, vulnerability intelligence, MITRE ATT&CK contextualization, packet capture analysis, live threat feed tracking, breach lookup support, and alert generation. It also includes frontend presentation, backend orchestration, persistence, caching, and documentation design required to make the system operationally coherent.",
        "The current scope does not include enterprise SIEM ingestion, multi-tenant access control, on-premises agent deployment, EDR-level telemetry collection, or full SOC case management workflows. These areas are treated as future extensions rather than mandatory deliverables within the current project timeline.",
        "Within the blackbook itself, the scope is extended beyond code implementation to include planning, literature review, software requirements, architecture, testing strategy, outputs, business advantages, and future expansion paths so that the report matches the expectations of a comprehensive MIT ADT project submission.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 2: PROBLEM STATEMENT",
    "2.1 Introduction",
    [
        "The cybersecurity domain generates an enormous amount of intelligence, but intelligence alone does not create security outcomes. Outcomes depend on how quickly and correctly analysts can transform raw observations into prioritized decisions. That transformation is where fragmentation causes the most damage. When critical evidence is spread across unrelated services, every investigation becomes slower and more error-prone than necessary.",
        "CyberRegis addresses a workflow-level problem rather than a single detection problem. The system is not built to replace all security tooling. It is built to unify the most common investigative actions into one efficient sequence. This distinction is important because the platform is optimized for operational decision support, not only for data display.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 2: PROBLEM STATEMENT",
    "2.2 Background of the Problem",
    [
        "Across institutional, startup, and mid-sized enterprise environments, security teams often depend on a patchwork of browser-based lookups and disconnected dashboards. A suspicious IP might be checked in AbuseIPDB, then Shodan, then GreyNoise, then geolocation sources. A malicious domain may require verification in VirusTotal, Google Safe Browsing, and WHOIS history. A newly published CVE requires separate exploration through NVD, vendor advisories, and ATT&CK-aligned tradecraft references.",
        "The problem is not merely the number of tools. It is the lack of integrated context. Each source speaks in its own data model, confidence language, and presentation style. Analysts must normalize mental models manually. Under alert fatigue, that manual normalization becomes a reliability risk. Organizations lose time not because data is unavailable, but because useful context arrives in fragments.",
        "This background is especially relevant in high-pressure workflows such as phishing investigation, exposed service review, suspicious outbound traffic analysis, and vulnerability triage after public disclosure. In each of these workflows, time and consistency matter.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 2: PROBLEM STATEMENT",
    "2.3 Statement of the Problem",
    [
        "Security analysts currently lack an accessible, unified platform that brings together multi-source threat intelligence, domain and IP enrichment, vulnerability intelligence, packet analysis, AI-guided explanation, and alerting support in a single operational interface. As a result, analysts must correlate disconnected evidence manually, which increases response time and introduces inconsistency across investigations.",
        "The core problem can therefore be stated as follows: how can a single product be designed to reduce fragmentation in cyber investigations while preserving technical depth, real-time relevance, and operational usability for analysts working under time pressure? CyberRegis is the proposed answer to that question.",
    ],
    bullets_list=[
        "Fragmented threat intelligence sources",
        "Repeated manual investigation steps",
        "Delayed real-time visibility into active indicators",
        "Weak contextual connection between CVEs, infrastructure exposure, and observed network behavior",
        "Inefficient communication of high-priority findings to stakeholders",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 2: PROBLEM STATEMENT",
    "2.4 Scope of the Problem",
    [
        "The problem addressed by CyberRegis is scoped to analyst-facing intelligence workflows. It focuses on the collection, normalization, visualization, enrichment, and prioritization of security signals that are commonly checked during triage and investigation. It does not attempt to solve endpoint telemetry collection, enterprise log ingestion at SIEM scale, or digital forensics beyond the level of packet capture analysis.",
        "This scoping keeps the project aligned with an implementable academic timeline while still covering a highly relevant slice of practical cybersecurity operations. It also enables deeper treatment of analyst workflow quality, which is a major differentiator of the final platform.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 3: LITERATURE REVIEW",
    "3.1 Commercial Tools",
    [
        "Commercial platforms such as Splunk Enterprise Security, IBM QRadar, Microsoft Sentinel, Palo Alto Cortex XDR, and Recorded Future provide broad security visibility, analytics, and enrichment capabilities. Their strength lies in scale, integration breadth, and enterprise support. However, these platforms usually require significant financial commitment, complex onboarding, and dedicated administrative maturity to achieve full value.",
        "For many organizations and academic environments, the barrier is not only licensing cost but the operational overhead of standing up and tuning these systems. This means that although commercial platforms offer useful design lessons, they do not solve the accessibility gap faced by small teams and project environments.",
        "CyberRegis borrows the workflow principle of unified investigation while avoiding enterprise-only assumptions. It aims for useful integration density without imposing heavyweight infrastructure expectations.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 3: LITERATURE REVIEW",
    "3.2 Open Source and Academic Systems",
    [
        "Open-source platforms such as MISP, TheHive, Cortex, OpenCTI, Wazuh, and Zeek each contribute valuable capabilities. MISP is strong for indicator sharing, TheHive supports case management, Cortex provides analyzers and responders, and OpenCTI focuses on structured intelligence knowledge graphs. Academic prototypes often focus on narrower research problems such as phishing detection, malware classification, packet inspection, or anomaly detection pipelines.",
        "What these systems reveal is that strong technical building blocks exist, but product coherence is often distributed across multiple deployments. For example, a user may still need separate interfaces for intelligence lookup, enrichment, case handling, and packet analysis. In academic papers, the scope is frequently deep but narrow, emphasizing model performance over daily analyst experience.",
        "CyberRegis synthesizes these lessons by prioritizing the analyst-facing layer. The focus is not solely on intelligence collection or model performance. The focus is on how an analyst moves from a question to a decision with minimal unnecessary friction.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 3: LITERATURE REVIEW",
    "3.3 Comparative Gap Analysis",
    [
        "A cross-comparison of commercial and open-source solutions shows that no single accessible platform in the examined set combines domain reputation, IP enrichment, breach checking, CVE tracking, ATT&CK contextualization, packet capture analysis, AI explanation, alerting, and lightweight deployment in one cohesive application. Existing systems either excel in scale but sacrifice accessibility, or remain accessible but fragmented across multiple deployments.",
        "This gap validates the need for CyberRegis as a unification platform. The system is not meant to surpass every specialized tool in its niche. Instead, its value proposition lies in combining enough of the right capabilities to make investigation faster, clearer, and more repeatable in realistic operating conditions.",
    ],
    table_headers=["Platform", "Unified Analyst UI", "Threat Intel", "PCAP Support", "AI Guidance", "Accessibility"],
    table_data=[
        ["CyberRegis", "Yes", "Yes", "Yes", "Yes", "High"],
        ["VirusTotal", "No", "Yes", "No", "No", "Medium"],
        ["Shodan", "No", "Partial", "No", "No", "Medium"],
        ["MISP", "Partial", "Yes", "No", "No", "Medium"],
        ["IBM QRadar", "Yes", "Yes", "Partial", "No", "Low"],
    ],
    widths=[1.5, 1.0, 0.8, 0.8, 0.8, 1.0],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 3: LITERATURE REVIEW",
    "3.4 Key Findings",
    [
        "The literature and product review produce four key findings. First, integration density matters more than raw tool count when analyst speed is the goal. Second, context enrichment is more valuable than isolated scores. Third, accessible security tooling still lacks high-quality explanation layers for less technical stakeholders. Fourth, packet analysis and vulnerability context are rarely presented side by side in lightweight systems even though they are frequently relevant in the same investigation.",
        "These findings directly inform the design of CyberRegis. Every major module in the platform exists because it closes one or more of the identified gaps while remaining realistically implementable within the project timeline.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 4: CONCEPTS AND METHODS",
    "4.1 Threat Intelligence Aggregation",
    [
        "Threat intelligence aggregation in CyberRegis refers to the systematic retrieval and normalization of security data from multiple APIs into a single presentation layer. Instead of exposing raw vendor-specific formats directly to the user, the backend transforms each response into a predictable internal structure with fields such as severity, confidence, supporting evidence, detection source, and recommended action.",
        "This normalization step is essential because external platforms vary in naming conventions, confidence semantics, and response depth. A unified platform must make these outputs comparable. CyberRegis achieves this through adapter functions in the backend that translate each API response into a consistent schema before returning it to the frontend.",
        "The practical benefit is that users can evaluate multiple signals side by side without mentally remapping each source. That directly improves both usability and analytical quality.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 4: CONCEPTS AND METHODS",
    "4.2 Correlation and Risk Scoring",
    [
        "Correlation is the process of combining independent observations into a stronger analytical conclusion. In CyberRegis, a malicious IP classification gains weight if AbuseIPDB reports are high, Shodan shows exposed services, and GreyNoise identifies hostile behavior. Likewise, a domain's reputation becomes more meaningful when phishing flags, malware detections, and unsafe browsing indicators converge.",
        "To operationalize this, the system uses a weighted risk scoring model. The model is not presented as a machine learning classifier in the current version. Instead, it is an interpretable scoring framework in which each source contributes bounded evidence according to severity and reliability. This design was selected deliberately because explainability is critical in analyst tools.",
        "The weighted model also makes the product extensible. New intelligence sources can be added later by defining their evidence contribution without redesigning the whole scoring layer.",
    ],
    bullets_list=[
        "Source reliability weighting",
        "Indicator category weighting",
        "Historical recurrence sensitivity",
        "Observed exposure contextualization",
        "Analyst-readable explanation output",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 4: CONCEPTS AND METHODS",
    "4.3 Vulnerability Intelligence and ATT&CK Mapping",
    [
        "Vulnerability intelligence in CyberRegis is not limited to listing CVE metadata. The project connects vulnerability records to operational context by highlighting CVSS severity, affected assets or software families, public disclosure relevance, and MITRE ATT&CK techniques associated with likely exploitation behavior. This approach transforms static CVE data into decision support.",
        "The MITRE ATT&CK mapping concept is particularly important because it helps bridge the gap between vulnerability awareness and attack understanding. When a CVE is tied to techniques such as initial access, privilege escalation, or command and control, analysts can reason about adversary behavior rather than only patch references.",
        "This method is aligned with industry practice, where ATT&CK is used to translate technical findings into structured adversary tradecraft language that security teams can operationalize.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 4: CONCEPTS AND METHODS",
    "4.4 PCAP Analysis",
    [
        "Packet capture analysis provides network-level visibility into traffic behavior. Within CyberRegis, PCAP analysis is used to extract protocol distributions, identify DNS requests, highlight unusual communication patterns, and recover network indicators that can be enriched through the broader threat intelligence pipeline. This makes the module especially useful for network troubleshooting, incident investigation, and IOC discovery.",
        "The method emphasizes practical summarization rather than raw packet dumping. Analysts rarely benefit from seeing every packet field unless they are in a full forensic workflow. Instead, CyberRegis prioritizes counts, protocol mix, suspicious hosts, and indicator extraction so that a PCAP becomes a structured operational artifact rather than a low-level binary capture.",
        "This design keeps the feature useful within a web dashboard while still preserving the technical depth expected in a cybersecurity project.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 4: CONCEPTS AND METHODS",
    "4.5 AI-Assisted Investigation",
    [
        "The AI layer in CyberRegis is designed as a guidance mechanism, not an autonomous security engine. Google Gemini is used to interpret user questions, summarize technical context, explain why a signal matters, and suggest next investigative actions. This is particularly valuable when analysts need concise threat interpretation or when non-specialist stakeholders need readable explanations of security findings.",
        "The method relies on prompt control and domain restriction. The system prompt constrains the model to cybersecurity workflows and encourages practical, evidence-based responses. The model does not replace source data. Instead, it sits on top of it, turning evidence into explanation. This distinction is essential for trustworthy human-in-the-loop security tooling.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 5: PROJECT PLAN",
    "5.1 Development Methodology",
    [
        "CyberRegis was executed using an Agile sprint-based project model. The choice of Agile was appropriate because the product depended on iterative refinement, experimentation with multiple APIs, interface adjustments, and continuous validation of investigative usability. Requirements were refined throughout the project based on implementation learnings and integration constraints.",
        "The team followed short sprint cycles with regular review checkpoints. Each sprint targeted a coherent capability set such as core API integration, dashboard workflows, PCAP analysis, AI integration, or final validation. This structure improved visibility into progress while keeping risk manageable.",
        "The Agile approach also helped distribute ownership clearly among frontend, backend, dashboard, and integration-heavy tasks, which was important for a four-member team with overlapping responsibilities.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 5: PROJECT PLAN",
    "5.2 Sprint Plan",
    [
        "The project execution timeline was divided into structured sprints from early January to late April 2026. Each sprint concluded with a review of deliverables, blockers, and follow-up actions. This ensured that documentation and code evolved together rather than diverging until the final submission stage.",
    ],
    table_headers=["Sprint", "Date Range", "Focus Area", "Lead Owner"],
    table_data=[
        ["Sprint 1", "01 Jan - 07 Jan", "Problem framing, research, feature scoping", "Kathan"],
        ["Sprint 2", "08 Jan - 17 Jan", "Base frontend and backend scaffolding", "Dev"],
        ["Sprint 3", "18 Jan - 28 Jan", "Threat lookup APIs and UI wiring", "Kathan"],
        ["Sprint 4", "29 Jan - 08 Feb", "Dashboard cards, storage, history", "Darshan"],
        ["Sprint 5", "09 Feb - 18 Feb", "CVE and MITRE modules", "Dev"],
        ["Sprint 6", "19 Feb - 28 Feb", "Domain and IP enrichment enhancements", "Aryan"],
        ["Sprint 7", "01 Mar - 11 Mar", "PCAP analysis module", "Kathan"],
        ["Sprint 8", "12 Mar - 22 Mar", "AI chatbot integration", "Dev"],
        ["Sprint 9", "23 Mar - 02 Apr", "Alerting and monitoring", "Darshan"],
        ["Sprint 10", "03 Apr - 12 Apr", "Security hardening and caching", "Aryan"],
        ["Sprint 11", "13 Apr - 20 Apr", "Testing and output polishing", "Kathan"],
        ["Sprint 12", "21 Apr - 27 Apr", "Documentation and final closure", "Shared"],
    ],
    widths=[0.9, 1.5, 2.9, 1.0],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 5: PROJECT PLAN",
    "5.3 Work Breakdown and Team Roles",
    [
        "The work breakdown structure was created around functional ownership rather than only technology ownership. This allowed the team to think in product slices. For example, the dashboard stream required API access, UI work, data shaping, and layout coherence. Treating it as a cross-functional feature reduced handoff friction.",
        "Although each member had primary ownership areas, the project was reviewed collaboratively to keep architectural and documentation consistency high. This also reduced the risk of isolated knowledge silos near submission time.",
    ],
    table_headers=["Member", "Primary Ownership", "Secondary Contribution", "Outcome"],
    table_data=[
        ["Kathan", "Product flow, threat modules, integration planning", "Documentation, validation, final polish", "Platform coherence"],
        ["Dev", "Backend services, data handling, CVE logic", "AI integration, route structuring", "Reliable processing layer"],
        ["Aryan", "Frontend refinement, resource pages, usability", "UI consistency and responsiveness", "Readable operator UI"],
        ["Darshan", "Dashboard assembly, monitoring workflows", "Output curation and visuals", "Analyst-facing dashboards"],
    ],
    widths=[1.1, 2.2, 2.0, 1.1],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 5: PROJECT PLAN",
    "5.4 Risk Register and Milestones",
    [
        "Every multi-API product faces dependency risk. External APIs can fail, rate limits can disrupt development, and inconsistent payloads can break assumptions. CyberRegis therefore tracked technical and delivery risks explicitly. This included API availability, payload variability, deadline compression, and documentation lag risk.",
        "Milestones were mapped to working demonstrations rather than only code completion. This was important because a feature is only meaningful in a product like CyberRegis when it behaves coherently from input to result presentation.",
    ],
    table_headers=["Risk", "Impact", "Mitigation", "Milestone Tied"],
    table_data=[
        ["API rate limits", "High", "Caching and graceful fallback handling", "Sprint 10"],
        ["Payload inconsistency", "High", "Normalized adapter layer", "Sprint 3-6"],
        ["UI complexity growth", "Medium", "Reusable cards and section templates", "Sprint 4"],
        ["Testing delay", "Medium", "Reserved final validation sprint", "Sprint 11"],
        ["Documentation mismatch", "Medium", "Parallel documentation updates", "All sprints"],
    ],
    widths=[1.6, 0.8, 2.5, 1.1],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 6: SOFTWARE REQUIREMENTS AND SPECIFICATION",
    "6.1 Introduction",
    [
        "The Software Requirements Specification for CyberRegis defines the expected behavior, operational constraints, technical stack expectations, and security controls for the system. Because the project aims to emulate an industry-relevant platform rather than a narrowly academic proof of concept, requirements are expressed in a product-oriented manner.",
        "This chapter is important because it establishes what the system must do before discussing how it is implemented. It also makes evaluation more objective by separating requirements from implementation preference.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 6: SOFTWARE REQUIREMENTS AND SPECIFICATION",
    "6.2 Overall Description",
    [
        "CyberRegis is a web-based analyst platform used for cyber threat lookups, enrichment, vulnerability tracking, AI-assisted explanation, packet capture analysis, alerting, and reporting support. The system targets users who need investigative clarity more than raw telemetry volume. Its architecture assumes internet connectivity for external intelligence APIs and authenticated access for protected workflows.",
        "The frontend must remain responsive across desktop and laptop form factors. The backend must reliably orchestrate external services, apply caching, and store reusable investigation data. The database must support historical lookup retention and future reporting use cases.",
    ],
    bullets_list=[
        "User class: student analyst, SOC trainee, security engineer, academic evaluator",
        "Deployment model: web application with backend API and database",
        "Operating mode: on-demand lookup plus background alerting",
        "Primary value: reduced investigation friction and better context visibility",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 6: SOFTWARE REQUIREMENTS AND SPECIFICATION",
    "6.3 Specific Requirements",
    [
        "Specific requirements are grouped into functional, technical, and security categories. Functional requirements define the analyst-facing capabilities. Technical requirements define runtime and component behavior. Security requirements define how the system protects credentials, controls access, validates input, and reduces misuse risk.",
    ],
    table_headers=["ID", "Requirement", "Priority", "Status"],
    table_data=[
        ["FR-01", "Domain and URL reputation analysis", "High", "Implemented"],
        ["FR-02", "IP reputation and infrastructure enrichment", "High", "Implemented"],
        ["FR-03", "CVE search and vulnerability tracking", "High", "Implemented"],
        ["FR-04", "MITRE ATT&CK contextual mapping", "High", "Implemented"],
        ["FR-05", "PCAP upload and analysis", "High", "Implemented"],
        ["FR-06", "AI chatbot assistance", "High", "Implemented"],
        ["FR-07", "Telegram alerting", "Medium", "Implemented"],
        ["FR-08", "History and caching layer", "Medium", "Implemented"],
    ],
    widths=[0.8, 3.5, 0.8, 1.0],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 6: SOFTWARE REQUIREMENTS AND SPECIFICATION",
    "6.4 System Features",
    [
        "CyberRegis exposes its capabilities as focused operator features rather than as raw API forms. This matters because the product is designed to be used under investigative pressure. Features therefore need clear entry points, predictable layouts, and low ambiguity in outputs.",
    ],
    bullets_list=[
        "Unified dashboard for quick navigation and monitoring",
        "Domain reconnaissance and URL threat review",
        "IP intelligence scanner with multi-source enrichment",
        "Network log analysis through PCAP upload",
        "Security and advanced modules for future expansion",
        "Resources page for curated learning and reference support",
        "Switchable result presentation modes such as normal and JSON view",
        "Cached results display with timestamp context",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 6: SOFTWARE REQUIREMENTS AND SPECIFICATION",
    "6.5 Data and Security Requirements",
    [
        "Because CyberRegis processes intelligence queries and user-submitted packet captures, data handling and security were treated as first-order concerns. API keys are stored outside source code, user inputs are validated before backend processing, and external service calls are proxied through the backend to avoid exposing credentials to the browser.",
        "Data retention requirements are intentionally modest in the current version, focusing on investigation history rather than broad telemetry warehousing. This keeps the project lightweight while still enabling repeatability, review, and learning value from prior searches.",
    ],
    bullets_list=[
        "Environment-variable based API key storage",
        "Input validation and sanitization on all dynamic endpoints",
        "Server-side only external intelligence calls",
        "Caching with bounded lifetime to reduce unnecessary API exposure",
        "Graceful handling of upstream service errors",
        "Audit-friendly history storage for repeated lookups",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 7: BLOCK DIAGRAM",
    "7.1 High Level Block Diagram",
    [
        "The CyberRegis block diagram is organized around clear responsibility boundaries. The browser hosts the user experience, the frontend structures interaction, the backend coordinates logic, the cache reduces latency, the database stores reusable history, and the external APIs supply domain-specific intelligence. This separation enables independent evolution of interface, orchestration, and data persistence layers.",
    ],
    mono=[
        "+--------------------+",
        "|  Analyst Browser   |",
        "+---------+----------+",
        "          |",
        "          v",
        "+--------------------+      +--------------------+",
        "| Next.js Frontend   | ---> |  Flask API Layer   |",
        "+---------+----------+      +----+---------+------+",
        "          |                        |         |",
        "          |                        |         +--> External Threat APIs",
        "          |                        |",
        "          |                        +--> Redis Cache",
        "          |",
        "          +-----------------------------> PostgreSQL History",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 7: BLOCK DIAGRAM",
    "7.2 Data Flow and Interaction Mapping",
    [
        "The data flow begins when a user submits an investigation request such as a domain lookup or PCAP file. The frontend validates the request format and forwards it to the backend. The backend then checks cache availability, enriches through one or more intelligence APIs, normalizes results, optionally stores the interaction, and returns a structured response to the frontend. If the result crosses a severity threshold, the alerting subsystem triggers Telegram delivery.",
        "This flow emphasizes consistent response handling. Whether the input is a domain, an IP address, a CVE identifier, or a PCAP file, the user should receive results in a predictable visual grammar. That consistency is a major usability objective of the system.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 8: SYSTEM ARCHITECTURE / IMPLEMENTATION",
    "8.1 Frontend Implementation",
    [
        "The frontend is implemented using Next.js 14 with the app router model. This enables route-based structuring for major modules such as dashboard, CVE, monitoring, history, resources, and threat-intel views. Tailwind CSS and shadcn/ui components are used to keep the interface consistent while retaining flexibility for custom security-specific cards and panels.",
        "The design language of the interface favors clarity over ornamentation. Since CyberRegis is an analyst tool, components are optimized for fast scanning, stable layout behavior, direct calls to action, and minimal distraction. Dark backgrounds with high-contrast green indicators are used to reinforce a cybersecurity monitoring context.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 8: SYSTEM ARCHITECTURE / IMPLEMENTATION",
    "8.2 Backend Implementation",
    [
        "The backend is implemented in Python Flask as a lightweight orchestration layer for intelligence retrieval, parsing, scoring, caching, alerting, and response formatting. This choice balances developer velocity with sufficient structure for a project of this scale. Flask's ecosystem also makes it easy to add rate limiting, caching, and modular routing without introducing unnecessary framework weight.",
        "Each intelligence source is integrated through explicit processing functions so that parsing logic remains isolated and testable. This reduces breakage when external providers change payload formats and keeps the implementation maintainable.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 8: SYSTEM ARCHITECTURE / IMPLEMENTATION",
    "8.3 API Integration Layer",
    [
        "The API integration layer is the operational heart of CyberRegis. It coordinates threat lookup sources, maps payloads into shared structures, and ensures that the frontend receives stable output even when external providers differ substantially in richness or reliability. This layer also enables the product to be future-proofed by making integrations pluggable rather than tightly embedded into UI logic.",
        "In implementation terms, the layer provides clear routing between user requests and provider-specific adapters. That makes the system easier to test, easier to expand, and safer to debug when one provider fails or changes behavior.",
    ],
    table_headers=["Integration", "Purpose", "Returned Context", "Mode"],
    table_data=[
        ["VirusTotal", "Domain, URL, hash scanning", "Detection counts, categories, votes", "Live API"],
        ["AbuseIPDB", "IP abuse review", "Confidence score, reports, usage type", "Live API"],
        ["Shodan", "Infrastructure exposure", "Open ports, banners, org, hostnames", "Live API"],
        ["GreyNoise", "Internet noise classification", "Noise vs suspicious labeling", "Live API"],
        ["NVD", "CVE intelligence", "CVSS, summaries, references", "Live API / Cached"],
        ["Gemini", "AI explanation", "Contextual analyst guidance", "Live API"],
    ],
    widths=[1.2, 1.8, 2.5, 0.8],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 8: SYSTEM ARCHITECTURE / IMPLEMENTATION",
    "8.4 Database, Caching, and Background Processing",
    [
        "PostgreSQL is used to persist reusable investigation history and future-ready reporting data. Redis acts as a short-lived caching layer that reduces external API dependence, lowers average response time, and improves the user experience for repeated lookups. This pairing gives CyberRegis both persistence and speed without introducing unnecessary storage complexity.",
        "Background processing is used for alert emission and non-blocking operational tasks. Even in a student project, this separation is important because it aligns with real system design principles: user-facing responses should stay fast while notifications and supporting actions happen asynchronously where possible.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 8: SYSTEM ARCHITECTURE / IMPLEMENTATION",
    "8.5 Security Controls and Deployment",
    [
        "A cybersecurity platform must itself follow baseline security hygiene. CyberRegis therefore avoids client-side exposure of secrets, validates inbound requests, limits request frequency, and centralizes outbound intelligence calls in the backend. These controls reduce abuse potential and align the implementation with standard secure coding expectations.",
        "Deployment readiness was also considered. The frontend is compatible with modern serverless hosting patterns, while the backend can be containerized or deployed to lightweight cloud application platforms. This allows the product to move beyond a local demo when needed.",
    ],
    bullets_list=[
        "Environment variable based secret storage",
        "Backend-only access to external intelligence providers",
        "Rate limiting for abuse resistance",
        "Validation for file uploads and dynamic inputs",
        "Operational separation between UI and data services",
        "Cloud-friendly deployment posture",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 8: SYSTEM ARCHITECTURE / IMPLEMENTATION",
    "8.6 Testing and Validation Hooks",
    [
        "Validation in CyberRegis is implemented through a mix of code checks, live API testing, cached result verification, output inspection, and end-to-end interaction review. The presence of both normal and JSON result modes helps developers and evaluators validate the system at different abstraction levels. The normal mode emphasizes analyst usability, whereas JSON mode exposes structured payloads for debugging and correctness checks.",
        "The project also uses output screenshots as evidence of working modules, which strengthens the final report by linking the architecture narrative directly to deployed behavior.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 9: RESULT",
    "9.1 Validation Summary",
    [
        "CyberRegis achieved the primary outcome it was designed for: a single, working platform that unifies common threat intelligence and investigation workflows into a coherent analyst-facing interface. The final implementation supports threat lookups, vulnerability tracking, network capture review, AI-assisted security context, and visual output navigation, all within the same product environment.",
        "From a project quality perspective, the result is not only that features exist, but that they exist in an integrated manner. That integration quality is the most important success criterion of the system.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 9: RESULT",
    "9.2 Performance Results",
    [
        "Performance validation indicates that CyberRegis remains practically usable under normal project conditions. Cached requests return quickly, external lookups are normalized efficiently, and the dashboard flow remains understandable even when multiple data blocks are displayed together. Performance is strongly improved by the caching layer, particularly for repeated lookups and result revisits.",
    ],
    table_headers=["Scenario", "Observed Result", "Operational Interpretation", "Status"],
    table_data=[
        ["Cached lookup", "Sub-second return", "Good operator experience", "Pass"],
        ["Fresh intelligence lookup", "Provider dependent", "Acceptable for enrichment-heavy workflow", "Pass"],
        ["PCAP analysis", "Heavier but usable", "Reasonable for capture summarization", "Pass"],
        ["AI chatbot prompt", "Interactive latency", "Usable for analyst support", "Pass"],
    ],
    widths=[1.7, 1.5, 2.5, 0.8],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 9: RESULT",
    "9.3 Discussion",
    [
        "The strongest outcome of the project is workflow consolidation. Users are no longer forced to treat domain investigation, IP enrichment, CVE tracking, network review, and contextual explanation as separate browser tasks. That consolidation directly supports the thesis of the project and justifies the architectural choices made throughout development.",
        "At the same time, the results also reveal natural growth areas. Some outputs can be made richer, some alert thresholds can be made more adaptive, and some provider combinations can be expanded. These do not weaken the current deliverable. Instead, they show that the product has a credible path forward beyond the academic submission stage.",
    ],
)
doc.add_page_break()

chapter_title(doc, "CHAPTER 10: OUTPUTS")
section_title(doc, "10.1 Representative Interface Outputs")
body_paragraph(doc, "This chapter documents representative outputs captured from the CyberRegis application. The screenshots demonstrate the implemented interface, interaction patterns, and result presentation quality across the major investigation modules.")
doc.add_page_break()

output_commentary = [
    "This output demonstrates the deployed CyberRegis interface in a live browser environment. The visual structure shows the dark operational dashboard style, direct module navigation, and the product positioning as a practical analyst workbench.",
    "This screenshot highlights how CyberRegis presents investigation results in a readable, operationally useful panel instead of returning raw provider output only. This supports faster triage and lowers interpretation effort.",
    "The output also reflects the product's emphasis on compact security context such as status labels, structured fields, and result summaries that can be scanned quickly during analysis.",
    "This page is important as evidence that the project moved beyond backend integration and produced a coherent interface layer, which is essential for a final-year product-oriented cybersecurity submission.",
    "The screen demonstrates the continuity between user input, platform response, and structured result interpretation. That continuity is one of the key quality goals of CyberRegis.",
    "This interface output supports the claim that the application is operationally usable and not merely a technical proof of API connectivity.",
    "The result view preserves enough detail for technical users while remaining accessible to reviewers and evaluators who need to understand what the platform actually delivers.",
    "This final output page reinforces the breadth of implemented functionality and shows that the system supports multiple analyst workflows within one coherent UI framework.",
    "The output chapter as a whole acts as product evidence and directly supports the technical narrative documented in the implementation chapters.",
]

for index, image_path in enumerate(screenshots[:9], start=1):
    caption = f"Figure {index + 4}: CyberRegis application output snapshot {index}"
    commentary = output_commentary[min(index - 1, len(output_commentary) - 1)]
    add_picture_page(doc, "CHAPTER 10: OUTPUTS", image_path, caption, commentary)
    if index != min(len(screenshots), 9):
        doc.add_page_break()

doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 11: ADVANTAGES",
    "11.1 Operational and Technical Advantages",
    [
        "CyberRegis delivers several advantages that are directly relevant to contemporary cybersecurity operations. The first and most important is workflow unification. When common investigation actions are performed in one place, analysts preserve context, build confidence faster, and reduce duplicated effort.",
        "The second advantage is explainability. By combining structured enrichment with AI-assisted explanation, the system helps both technical and semi-technical stakeholders understand why a result matters. This improves communication between analysts and decision-makers.",
    ],
    bullets_list=[
        "Reduced context switching during investigation",
        "Improved visibility into domains, IPs, CVEs, and packet captures",
        "Integrated operational dashboard style output",
        "Faster prioritization through normalized risk context",
        "Reusable investigation history",
        "Accessible architecture for academic and lightweight deployment use cases",
        "Extensible design for future security integrations",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 12: CONCLUSION",
    "12.1 Closing Summary",
    [
        "CyberRegis successfully addresses the central problem identified at the start of this report: the fragmentation of modern cybersecurity investigation workflows. By combining intelligence aggregation, vulnerability context, packet capture review, alerting, and AI-supported explanation in one product, the project creates a strong foundation for faster and more coherent security analysis.",
        "The final implementation is technically credible, operationally readable, and aligned with industry-relevant security needs. Just as importantly, the blackbook documents the project in a format that reflects full-stack software engineering discipline rather than only feature delivery. This makes CyberRegis a strong final-year submission and a credible base for future product evolution.",
    ],
)
doc.add_page_break()

add_single_page_section(
    doc,
    "CHAPTER 13: FUTURE WORK",
    "13.1 Product and Research Expansion",
    [
        "Future work for CyberRegis naturally falls into two tracks: product maturity and research depth. On the product side, the platform can evolve toward multi-user collaboration, advanced reporting, richer case management, custom alert rules, and deeper integration with enterprise infrastructure. On the research side, the scoring and explanation layers can be enhanced with adaptive models, analyst feedback loops, and automated behavior clustering.",
        "Because the current system already centralizes several strong intelligence workflows, future development can be additive rather than corrective. That is a sign that the present architecture is stable enough to support growth.",
    ],
    bullets_list=[
        "Role-based authentication and team workspaces",
        "Configurable alert policies and watchlists",
        "Expanded threat feed and malware sandbox integrations",
        "Cloud-native deployment pipeline and CI/CD hardening",
        "ML-assisted prioritization from historical analyst feedback",
        "Case export and executive reporting modules",
    ],
)
doc.add_page_break()

chapter_title(doc, "BIBLIOGRAPHY")
bibliography_entries = [
    "[1] Next.js Documentation, Vercel, https://nextjs.org/docs",
    "[2] Flask Documentation, Pallets Projects, https://flask.palletsprojects.com",
    "[3] PostgreSQL Documentation, PostgreSQL Global Development Group, https://www.postgresql.org/docs/",
    "[4] Redis Documentation, Redis Ltd., https://redis.io/docs/",
    "[5] VirusTotal API Reference, Google, https://developers.virustotal.com/reference/overview",
    "[6] AbuseIPDB API Documentation, https://docs.abuseipdb.com/",
    "[7] Shodan Developer Documentation, https://developer.shodan.io/api",
    "[8] GreyNoise Developer Documentation, https://developer.greynoise.io/",
    "[9] Google Safe Browsing API Documentation, https://developers.google.com/safe-browsing",
    "[10] National Vulnerability Database API, NIST, https://nvd.nist.gov/developers",
    "[11] MITRE ATT&CK Framework, https://attack.mitre.org/",
    "[12] Have I Been Pwned API, https://haveibeenpwned.com/API/v3",
    "[13] Telegram Bot API, https://core.telegram.org/bots/api",
    "[14] Google Gemini API Documentation, https://ai.google.dev/",
    "[15] dpkt Python Library Documentation, https://dpkt.readthedocs.io/",
    "[16] OWASP Top 10, https://owasp.org/www-project-top-ten/",
    "[17] MISP Project Documentation, https://www.misp-project.org/",
    "[18] OpenCTI Documentation, https://docs.opencti.io/",
    "[19] Zeek Documentation, https://docs.zeek.org/",
    "[20] Suricata Documentation, https://docs.suricata.io/",
]
for entry in bibliography_entries:
    body_paragraph(doc, entry, indent=False, size=11, after=2)
doc.add_page_break()

chapter_title(doc, "ANNEXURE A: PUBLICATION DRAFT")
section_title(doc, "A.1 Draft Conference Paper Abstract")
body_paragraph(doc, "CyberRegis proposes a unified analyst-facing threat intelligence platform that reduces operational fragmentation in cybersecurity investigations. The system aggregates multi-source intelligence, contextualizes indicators through vulnerability and MITRE ATT&CK mappings, supports PCAP-based network summarization, and delivers AI-assisted threat interpretation using Google Gemini. Built with Next.js, Flask, PostgreSQL, and Redis, the platform demonstrates how lightweight full-stack engineering can produce practical analyst tooling with strong academic and industry relevance.")
body_paragraph(doc, "The contribution of the work lies not only in the integration of multiple security services, but in the deliberate design of a coherent investigation workflow. Rather than exposing raw API outputs independently, CyberRegis normalizes, enriches, and presents information in a way that supports faster triage and clearer decision-making. This makes the platform suitable as both an educational cybersecurity product and a base for future operational expansion.")
body_paragraph(doc, "Keywords: cyber threat intelligence, security operations, IOC enrichment, vulnerability context, ATT&CK mapping, packet analysis, AI-assisted cybersecurity.")
doc.add_page_break()

chapter_title(doc, "ANNEXURE B: PLAGIARISM AND CONTRIBUTION NOTE")
section_title(doc, "B.1 Submission Note")
body_paragraph(doc, "The formal plagiarism report is to be attached at final submission after institutional verification and export from the approved plagiarism checking workflow. The current annexure page is included to preserve the report structure expected in the MIT ADT blackbook template.")
section_title(doc, "B.2 Team Contribution Note")
for name, enroll in TEAM_MEMBERS:
    body_paragraph(doc, f"{name} ({enroll}) contributed to planning, implementation review, testing, and final documentation of CyberRegis.", indent=False, size=11)

doc.save(BLACKBOOK_PATH)

print(f"Blackbook saved: {BLACKBOOK_PATH}")
print("Template branding source: MIT ADT reference PDF")
print("Designed minimum page layout: 63+ pages based on explicit section pagination")

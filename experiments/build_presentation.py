"""Generate an editable PowerPoint (.pptx) version of the project
presentation -- same real content/narrative as the HTML slide deck, in a
format you can open in PowerPoint/Keynote/Google Slides and edit directly.

Usage:
    python experiments/build_presentation.py
    # writes TLS_Fingerprinting_Presentation.pptx to the project root
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = ROOT / "TLS_Fingerprinting_Presentation.pptx"

# ---- palette (same tokens as the HTML deck, dark theme) --------------------
BG = RGBColor(0x0A, 0x0E, 0x17)
CARD = RGBColor(0x12, 0x18, 0x26)
BORDER = RGBColor(0x23, 0x2B, 0x3D)
TEXT = RGBColor(0xED, 0xEF, 0xF4)
MUTED = RGBColor(0x9A, 0xA3, 0xB5)
FAINT = RGBColor(0x69, 0x72, 0x8A)
ACCENT = RGBColor(0xE8, 0xA3, 0x3D)
OK = RGBColor(0x49, 0xC7, 0x9A)
FLAG = RGBColor(0xF1, 0x6A, 0x54)

FONT_TITLE = "Archivo"
FONT_BODY = "IBM Plex Sans"
FONT_MONO = "IBM Plex Mono"

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)
MARGIN = Inches(0.75)


def new_deck():
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H
    return prs


def add_slide(prs, number, total):
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank layout
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid()
    bg.fill.fore_color.rgb = BG
    bg.line.fill.background()
    bg.shadow.inherit = False
    # send background to back by re-inserting first in the spTree
    slide.shapes._spTree.remove(bg._element)
    slide.shapes._spTree.insert(2, bg._element)

    num_box = slide.shapes.add_textbox(MARGIN, SLIDE_H - Inches(0.55), Inches(2), Inches(0.4))
    tf = num_box.text_frame
    tf.text = f"{number:02d} / {total}"
    run = tf.paragraphs[0].runs[0]
    run.font.name = FONT_MONO
    run.font.size = Pt(11)
    run.font.color.rgb = FAINT
    return slide


def add_textbox(slide, left, top, width, height, text, font=FONT_BODY,
                 size=18, color=TEXT, bold=False, align=PP_ALIGN.LEFT,
                 line_spacing=1.15, anchor=None):
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    if anchor is not None:
        tf.vertical_anchor = anchor
    lines = text.split("\n")
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.alignment = align
        p.line_spacing = line_spacing
        for run in p.runs:
            run.font.name = font
            run.font.size = Pt(size)
            run.font.color.rgb = color
            run.font.bold = bold
    return box


def add_eyebrow(slide, text, top=Inches(0.65)):
    add_textbox(slide, MARGIN, top, Inches(10), Inches(0.4), text.upper(),
                font=FONT_MONO, size=13, color=ACCENT, bold=False)


def add_title(slide, text, top=Inches(1.15), size=34, width=Inches(11.5)):
    add_textbox(slide, MARGIN, top, width, Inches(1.6), text,
                font=FONT_TITLE, size=size, color=TEXT, bold=True, line_spacing=1.05)


def add_body(slide, text, top, size=16, width=Inches(9.5), color=MUTED):
    add_textbox(slide, MARGIN, top, width, Inches(2), text,
                font=FONT_BODY, size=size, color=color, line_spacing=1.35)


def add_card(slide, left, top, width, height, lines, title=None):
    """lines: list of (text, font, size, color, bold)"""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.adjustments[0] = 0.06
    card.fill.solid()
    card.fill.fore_color.rgb = CARD
    card.line.color.rgb = BORDER
    card.line.width = Pt(1)
    card.shadow.inherit = False
    tf = card.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.25)
    tf.margin_right = Inches(0.25)
    tf.margin_top = Inches(0.2)
    tf.margin_bottom = Inches(0.2)

    all_lines = []
    if title:
        all_lines.append((title, FONT_MONO, 12, FAINT, False))
    all_lines.extend(lines)

    for i, (text, font, size, color, bold) in enumerate(all_lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = text
        p.line_spacing = 1.25
        p.space_after = Pt(4)
        for run in p.runs:
            run.font.name = font
            run.font.size = Pt(size)
            run.font.color.rgb = color
            run.font.bold = bold
    return card


def add_kpi_row(slide, items, top):
    left = MARGIN
    w = Inches(2.6)
    for n, label in items:
        add_textbox(slide, left, top, w, Inches(0.7), n, font=FONT_TITLE,
                    size=32, color=ACCENT, bold=True)
        add_textbox(slide, left, top + Inches(0.65), w, Inches(0.5), label,
                    font=FONT_BODY, size=12, color=MUTED)
        left = left + w


def add_table(slide, left, top, width, height, header, rows):
    n_rows = len(rows) + 1
    n_cols = len(header)
    gtable = slide.shapes.add_table(n_rows, n_cols, left, top, width, height).table
    for c, h in enumerate(header):
        cell = gtable.cell(0, c)
        cell.text = h
        cell.fill.solid()
        cell.fill.fore_color.rgb = CARD
        p = cell.text_frame.paragraphs[0]
        for run in p.runs:
            run.font.name = FONT_MONO
            run.font.size = Pt(11)
            run.font.color.rgb = FAINT
            run.font.bold = False
    for r, row in enumerate(rows, start=1):
        for c, val in enumerate(row):
            cell = gtable.cell(r, c)
            cell.text = val
            cell.fill.solid()
            cell.fill.fore_color.rgb = BG
            p = cell.text_frame.paragraphs[0]
            for run in p.runs:
                run.font.name = FONT_MONO if c > 0 else FONT_BODY
                run.font.size = Pt(12)
                run.font.color.rgb = TEXT if c == 0 else MUTED
    return gtable


def build():
    prs = new_deck()
    total = 12

    # 1. Title
    s = add_slide(prs, 1, total)
    add_eyebrow(s, "Computer Networks — Course Project", top=Inches(2.1))
    add_title(s, "TLS Fingerprinting", top=Inches(2.6), size=54)
    add_body(s, "Identifying who's really on the other end of an HTTPS "
                "connection — from the one moment before encryption locks in.",
             top=Inches(3.7), size=18, width=Inches(9))
    add_kpi_row(s, [("5", "real clients captured"), ("56", "tests passing"),
                    ("0", "fabricated results")], top=Inches(4.7))

    # 2. The blind spot
    s = add_slide(prs, 2, total)
    add_eyebrow(s, "The blind spot")
    add_title(s, "A server can't read what's inside HTTPS.")
    add_body(s, "Once a handshake completes, everything is encrypted. A "
                "scraper hammering a login page, a bot pretending to be a "
                "customer, a script bombarding an API — from outside, they "
                "look identical to a real visitor. Traffic volume alone "
                "won't tell you which requests are automated.",
             top=Inches(2.4), size=18, width=Inches(10.5))

    # 3. The unencrypted moment
    s = add_slide(prs, 3, total)
    add_eyebrow(s, "The one unencrypted moment")
    add_title(s, "Before encryption starts, every client says hello — in "
                 "plain text.", size=30)
    add_body(s, 'The TLS ClientHello: version, cipher list, extensions — sent '
                "unencrypted, always, by design. Different libraries write "
                'this "hello" differently. That structure is a fingerprint, '
                "sitting in the open.", top=Inches(2.3), size=17, width=Inches(10.5))
    add_card(s, MARGIN, Inches(4.1), Inches(11.5), Inches(1.3), [
        ("0040  00 00 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 00 0a  ...example.com..",
         FONT_MONO, 13, OK, False),
        ("0050  00 06 00 04 00 1d 00 17 00 0b 00 02 01 00 00 0d  ................",
         FONT_MONO, 13, MUTED, False),
    ])
    add_body(s, "Real bytes from pcaps/custom_client.pcap — the hostname is "
                "readable with no decryption at all.", top=Inches(5.6), size=13, color=FAINT)

    # 4. JA3 / JA3S mechanics
    s = add_slide(prs, 4, total)
    add_eyebrow(s, "The published technique — JA3 / JA3S")
    add_title(s, "Five fields, glued together, hashed.", size=32)
    add_card(s, MARGIN, Inches(2.5), Inches(5.6), Inches(3.2), [
        ("SSLVersion,Cipher,SSLExtension,\nEllipticCurve,PointFormat", FONT_MONO, 12, FAINT, False),
        ("771,4867-4866-4865-...,\n43-51-0-11-10-13-16,29-23-24-25,0", FONT_MONO, 13, TEXT, False),
        ("-> 375c6162a492dfbf2795909110ce8424", FONT_MONO, 13, ACCENT, True),
    ], title="JA3 — the client")
    add_card(s, Inches(6.65), Inches(2.5), Inches(5.6), Inches(3.2), [
        ("SSLVersion,Cipher,SSLExtension", FONT_MONO, 12, FAINT, False),
        ("771,4867,51-43", FONT_MONO, 13, TEXT, False),
        ("-> d75f9129bb5d05492a65ff78e081bcb2", FONT_MONO, 13, ACCENT, True),
    ], title="JA3S — the server's reply")
    add_body(s, "Real curl -> example.com capture. GREASE values (RFC 8701) "
                "are stripped from every field first.", top=Inches(6.0), size=13, color=FAINT)

    # 5. Architecture
    s = add_slide(prs, 5, total)
    add_eyebrow(s, "How it's built")
    add_title(s, "One pipeline, independently tested at every stage.", size=30)
    steps = [".pcap", "parser.py", "ja3 / ja3s / ja4", "database.py", "CLI report"]
    left = MARGIN
    top = Inches(3.0)
    w = Inches(2.05)
    for i, step in enumerate(steps):
        add_card(s, left, top, w, Inches(0.9), [(step, FONT_MONO, 13, TEXT, False)])
        left = left + w
        if i < len(steps) - 1:
            add_textbox(s, left, top + Inches(0.22), Inches(0.25), Inches(0.5), "->",
                        font=FONT_MONO, size=16, color=FAINT)
            left = left + Inches(0.25)
    add_body(s, "ClientHello/ServerHello bytes are parsed by hand against the "
                "RFC layout. Every arrow above is a separately unit-tested "
                "function.", top=Inches(4.4), size=16, width=Inches(10.5))

    # 6. Five clients table
    s = add_slide(prs, 6, total)
    add_eyebrow(s, "Experiment — five real clients, one real server")
    add_title(s, "Five different implementations. Five different fingerprints.", size=27)
    add_table(
        s, MARGIN, Inches(2.5), Inches(11.5), Inches(3.1),
        ["Client", "TLS library", "JA3 hash"],
        [
            ["curl 8.7.1", "SecureTransport / LibreSSL", "375c6162a492...ce8424"],
            ["openssl s_client", "OpenSSL 3.6.2", "0b85eb0d4981...f0ac5f"],
            ["Python stdlib ssl", "OpenSSL 3.6.2 (same lib!)", "f21f8e6cf70d...ef401c"],
            ["Chrome 151 (headless)", "BoringSSL", "81a2542af844...f2a626"],
            ["Hand-built ClientHello", "none — raw socket", "c53113116bb0...6fedc9"],
        ],
    )
    add_body(s, "openssl and Python share the exact same crypto library and "
                "still fingerprint differently — JA3 reflects configuration, "
                "not just which library is linked.", top=Inches(6.0), size=13, color=FAINT)

    # 7. The anomaly
    s = add_slide(prs, 7, total)
    add_eyebrow(s, "An unplanned discovery")
    add_title(s, "The same Chrome, twice, gave two different answers.", size=28)
    add_card(s, MARGIN, Inches(2.6), Inches(5.6), Inches(1.6),
             [("81a2542af8442fcd7802f178d9f2a626", FONT_MONO, 14, TEXT, False)],
             title="Run 1")
    add_card(s, Inches(6.65), Inches(2.6), Inches(5.6), Inches(1.6),
             [("825cf36b22c9ab3e25a5bc094aecde86", FONT_MONO, 14, FLAG, True)],
             title="Run 2 — same install, moments later")
    add_body(s, "Modern Chrome deliberately randomizes ClientHello extension "
                "order per connection, specifically to weaken fingerprinting "
                "like this. We didn't cite that as a fact — we reproduced it "
                "live, by accident, re-running our own experiment.",
             top=Inches(4.6), size=16, width=Inches(10.5))

    # 8. JA4 fix
    s = add_slide(prs, 8, total)
    add_eyebrow(s, "Built in response — JA4")
    add_title(s, "JA4 isolates what actually changed.", size=32)
    add_card(s, MARGIN, Inches(2.5), Inches(5.6), Inches(2.9), [
        ("8daaf6152771", FONT_MONO, 15, OK, True),
        ("8daaf6152771", FONT_MONO, 15, OK, True),
        ("Identical, both runs — sorted before\nhashing, immune to reordering.", FONT_BODY, 12, FAINT, False),
    ], title="Cipher segment")
    add_card(s, Inches(6.65), Inches(2.5), Inches(5.6), Inches(2.9), [
        ("806a8c22fdea   (16 extensions)", FONT_MONO, 14, TEXT, False),
        ("cb7bf5808d99   (17 extensions)", FONT_MONO, 14, FLAG, True),
        ("Genuinely different — Chrome sent one\nextra extension. JA4 reports that honestly.", FONT_BODY, 12, FAINT, False),
    ], title="Extension segment")
    add_body(s, "Validated against the official FoxIO spec's own worked "
                "examples — not just checked against itself.",
             top=Inches(5.7), size=13, color=FAINT)

    # 9. Bot detection
    s = add_slide(prs, 9, total)
    add_eyebrow(s, "From fingerprint to defense")
    add_title(s, "A script can lie about its identity. It can't fake its "
                 "handshake.", size=28)
    add_body(s, "A User-Agent header is a string the author typed — trivial "
                "to fake. The TLS ClientHello sent moments earlier is a "
                "structural property of whichever library is actually running.",
             top=Inches(2.3), size=16, width=Inches(10.5))
    add_card(s, MARGIN, Inches(3.5), Inches(11.5), Inches(2.6), [
        ("$ tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome", FONT_MONO, 13, FAINT, False),
        ("Claims to be:  Chrome", FONT_MONO, 13, MUTED, False),
        ("Measured JA3:  f21f8e6cf70d5980ecfe9fa2e0ef401c", FONT_MONO, 13, MUTED, False),
        ("VERDICT: *** MISMATCH — SUSPICIOUS ***", FONT_MONO, 14, FLAG, True),
        ("matches: Python 3.14.6 stdlib ssl (ssl.create_default_context)", FONT_MONO, 13, MUTED, False),
    ])

    # 10. Bombardment
    s = add_slide(prs, 10, total)
    add_eyebrow(s, "Under load")
    add_title(s, "5 rapid requests. 5 for 5, caught.", size=32)
    add_card(s, MARGIN, Inches(2.5), Inches(11.5), Inches(3.2), [
        ("$ python experiments/bombard_demo.py 5", FONT_MONO, 13, FAINT, False),
        ("request 1/5: JA3=f21f8e6c...  -> FLAGGED", FONT_MONO, 13, FLAG, False),
        ("request 2/5: JA3=f21f8e6c...  -> FLAGGED", FONT_MONO, 13, FLAG, False),
        ("request 3/5: JA3=f21f8e6c...  -> FLAGGED", FONT_MONO, 13, FLAG, False),
        ("request 4/5: JA3=f21f8e6c...  -> FLAGGED", FONT_MONO, 13, FLAG, False),
        ("request 5/5: JA3=f21f8e6c...  -> FLAGGED", FONT_MONO, 13, FLAG, False),
        ("Result: 5/5 requests correctly flagged.", FONT_MONO, 14, OK, True),
    ])
    add_body(s, "Each is an independent, real, live connection. The "
                "fingerprint is evidence about one connection's TLS stack — "
                "it doesn't dilute as request volume grows.",
             top=Inches(6.0), size=14, width=Inches(10.5))

    # 11. Limitations
    s = add_slide(prs, 11, total)
    add_eyebrow(s, "What this doesn't prove")
    add_title(s, "A fingerprint is a hint, not a verdict.", size=32)
    limits = [
        "Same hash != same software. Two unrelated programs on the same "
        "library/config fingerprint identically.",
        "JA3S depends on the client, too. Two of our own clients produced "
        "an identical JA3S against the same server.",
        "GREASE and reordering actively fight back. Chrome randomizes its "
        "own hello on purpose — we hit this live.",
        "Evasion is possible. Since the fingerprint is entirely "
        "client-controlled bytes, anyone can copy a browser's signature.",
        "Encrypted ClientHello looms. TLS 1.3's ECH threatens to encrypt "
        "away the exact fields this technique reads.",
    ]
    top = Inches(2.4)
    for i, text in enumerate(limits, start=1):
        add_textbox(s, MARGIN, top, Inches(0.6), Inches(0.5), f"{i:02d}",
                    font=FONT_MONO, size=14, color=ACCENT, bold=True)
        add_textbox(s, Inches(1.5), top, Inches(10.5), Inches(0.75), text,
                    font=FONT_BODY, size=15, color=MUTED, line_spacing=1.2)
        top = top + Inches(0.85)

    # 12. Close
    s = add_slide(prs, 12, total)
    add_eyebrow(s, "In summary")
    add_title(s, "Built, tested, and proven against real traffic.", size=32)
    add_body(s, "Every hash on every slide came from a real handshake with a "
                "real server — none of it invented.",
             top=Inches(2.3), size=18, width=Inches(10))
    add_kpi_row(s, [("56", "tests passing"), ("15", "measured DB entries"),
                    ("7", "real experiments"), ("2", "fingerprint schemes")],
                top=Inches(3.4))
    add_body(s, "TLS Fingerprinting — Computer Networks course project.",
             top=Inches(5.2), size=13, color=FAINT)

    prs.save(str(OUT_PATH))
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    build()

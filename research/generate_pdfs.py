#!/usr/bin/env python3
"""Generate professional PDF reports from markdown using markdown2 + weasyprint."""

import sys
import os
import markdown2
from weasyprint import HTML
from datetime import datetime

CSS = """
@page {
    size: A4;
    margin: 2.5cm 2cm 2.5cm 2cm;
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9px;
        color: #666;
    }
    @top-right {
        content: "RingWatch Research — TLP:WHITE";
        font-size: 8px;
        color: #999;
    }
}

body {
    font-family: 'DejaVu Sans', 'Segoe UI', Arial, sans-serif;
    font-size: 10.5px;
    line-height: 1.6;
    color: #222;
    max-width: 100%;
}

h1 {
    font-size: 22px;
    color: #1a1a2e;
    border-bottom: 3px solid #e94560;
    padding-bottom: 8px;
    margin-top: 0;
    page-break-before: avoid;
}

h2 {
    font-size: 17px;
    color: #16213e;
    border-bottom: 1px solid #ccc;
    padding-bottom: 4px;
    margin-top: 24px;
    page-break-after: avoid;
}

h3 {
    font-size: 14px;
    color: #0f3460;
    margin-top: 18px;
    page-break-after: avoid;
}

h4 {
    font-size: 12px;
    color: #333;
    margin-top: 14px;
}

p {
    margin: 6px 0;
    text-align: justify;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin: 10px 0;
    font-size: 9.5px;
    page-break-inside: avoid;
}

th {
    background-color: #16213e;
    color: white;
    padding: 6px 8px;
    text-align: left;
    border: 1px solid #16213e;
}

td {
    padding: 5px 8px;
    border: 1px solid #ddd;
    vertical-align: top;
}

tr:nth-child(even) {
    background-color: #f8f9fa;
}

code {
    font-family: 'DejaVu Sans Mono', 'Consolas', monospace;
    font-size: 9px;
    background-color: #f0f0f0;
    padding: 1px 4px;
    border-radius: 3px;
}

pre {
    background-color: #1e1e2e;
    color: #cdd6f4;
    padding: 12px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 9px;
    line-height: 1.4;
    page-break-inside: avoid;
}

pre code {
    background: none;
    padding: 0;
    color: inherit;
}

blockquote {
    border-left: 4px solid #e94560;
    margin: 10px 0;
    padding: 8px 16px;
    background-color: #fff3f3;
    color: #444;
}

strong {
    color: #16213e;
}

em {
    color: #555;
}

a {
    color: #0f3460;
    text-decoration: none;
}

hr {
    border: none;
    border-top: 1px solid #ddd;
    margin: 20px 0;
}

ul, ol {
    margin: 6px 0;
    padding-left: 24px;
}

li {
    margin: 3px 0;
}

/* Cover page styling */
.cover {
    text-align: center;
    padding-top: 120px;
    page-break-after: always;
}

.cover h1 {
    font-size: 28px;
    border: none;
    color: #16213e;
}

.cover .subtitle {
    font-size: 16px;
    color: #666;
    margin-top: 10px;
}

.cover .meta {
    font-size: 12px;
    color: #999;
    margin-top: 30px;
}

.cover .classification {
    display: inline-block;
    margin-top: 40px;
    padding: 6px 20px;
    border: 2px solid #e94560;
    color: #e94560;
    font-weight: bold;
    font-size: 14px;
}
"""

def md_to_pdf(md_path, pdf_path, title, subtitle):
    """Convert markdown to PDF with cover page."""
    with open(md_path, 'r') as f:
        md_content = f.read()
    
    # Convert markdown to HTML
    html_body = markdown2.markdown(md_content, extras=['tables', 'fenced-code-blocks', 'break-on-newline'])
    
    # Build full HTML with embedded CSS and cover page
    full_html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <style>{CSS}</style>
    </head>
    <body>
        <div class="cover">
            <h1>{title}</h1>
            <div class="subtitle">{subtitle}</div>
            <div class="classification">TLP:WHITE — PUBLIC RELEASE</div>
            <div class="meta">
                RingWatch Research Division<br>
                Dan Vladoiu — August 4, 2026<br>
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
            </div>
        </div>
        {html_body}
    </body>
    </html>
    """
    
    # Generate PDF
    HTML(string=full_html).write_pdf(pdf_path)
    print(f"Generated: {pdf_path}")

if __name__ == '__main__':
    base = os.path.dirname(os.path.abspath(__file__))
    
    reports = [
        (
            f'{base}/ring3-attack-surface-mapping.md',
            f'{base}/RingWatch_MITRE_ATTCK_Ring3_Mapping.pdf',
            'MITRE ATT&CK Surface Mapping: Ring -3 (Intel ME/CSME)',
            'Attack Techniques, CVE Catalog, and Threat Actor Analysis'
        ),
        (
            f'{base}/ring3-academic-conference-compendium.md',
            f'{base}/RingWatch_Academic_Conference_Compendium.pdf',
            'Academic & Conference Research Compendium: Ring -3',
            'Hacking Conferences, Academic Papers, Industry Research, and Community Tools'
        ),
        (
            f'{base}/ring3-defense-architecture.md',
            f'{base}/RingWatch_Defense_Architecture_Countermeasures.pdf',
            'Ring -3 Defense Architecture & Countermeasures',
            'A 7-Layer Defense Framework for Intel ME/CSME Threats'
        ),
    ]
    
    for md_path, pdf_path, title, subtitle in reports:
        if os.path.exists(md_path):
            md_to_pdf(md_path, pdf_path, title, subtitle)
        else:
            print(f"❌ Source not found: {md_path}")
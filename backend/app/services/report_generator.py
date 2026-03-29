"""
LaTeX Report Generator

Generates professional penetration testing reports in LaTeX format.
"""

import os
import json
import subprocess
import tempfile
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

import logging

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    title: str = "Penetration Testing Report"
    author: str = "All-Hack Security Scanner"
    company: str = ""
    classification: str = "CONFIDENTIAL"
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_remediation: bool = True
    include_appendix: bool = True


class LaTeXReportGenerator:
    """
    Generates LaTeX penetration testing reports.

    Features:
    - Executive summary
    - Vulnerability findings with severity
    - Technical details and PoC
    - Remediation recommendations
    - CVSS scoring
    - Charts and statistics
    """

    SEVERITY_COLORS = {
        "critical": "criticalcolor",
        "high": "highcolor",
        "medium": "mediumcolor",
        "low": "lowcolor",
        "info": "infocolor"
    }

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or tempfile.gettempdir()
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        config: ReportConfig = None
    ) -> str:
        """
        Generate a complete LaTeX report.

        Args:
            scan_data: Scan metadata (target, date, etc.)
            findings: List of vulnerability findings
            config: Report configuration

        Returns:
            Path to generated .tex file
        """
        config = config or ReportConfig()

        # Build document
        document = self._build_document(scan_data, findings, config)

        # Write to file
        filename = f"report_{scan_data.get('scan_id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tex"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(document)

        logger.info(f"[REPORT] Generated LaTeX report: {filepath}")
        return filepath

    def compile_pdf(self, tex_path: str) -> Optional[str]:
        """
        Compile LaTeX to PDF using pdflatex.

        Args:
            tex_path: Path to .tex file

        Returns:
            Path to generated PDF or None if compilation fails
        """
        try:
            output_dir = os.path.dirname(tex_path)

            # Run pdflatex twice for TOC and references
            for _ in range(2):
                result = subprocess.run(
                    ['pdflatex', '-interaction=nonstopmode', '-output-directory', output_dir, tex_path],
                    capture_output=True,
                    timeout=120
                )

            pdf_path = tex_path.replace('.tex', '.pdf')
            if os.path.exists(pdf_path):
                logger.info(f"[REPORT] Compiled PDF: {pdf_path}")
                return pdf_path
            else:
                logger.error(f"[REPORT] PDF compilation failed")
                return None

        except FileNotFoundError:
            logger.warning("[REPORT] pdflatex not found - returning .tex only")
            return None
        except subprocess.TimeoutExpired:
            logger.error("[REPORT] PDF compilation timed out")
            return None
        except Exception as e:
            logger.error(f"[REPORT] PDF compilation error: {e}")
            return None

    def _build_document(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        config: ReportConfig
    ) -> str:
        """Build the complete LaTeX document"""

        parts = [
            self._preamble(config),
            self._title_page(scan_data, config),
            r"\tableofcontents",
            r"\newpage",
        ]

        if config.include_executive_summary:
            parts.append(self._executive_summary(scan_data, findings))

        parts.append(self._findings_section(findings, config))

        if config.include_appendix:
            parts.append(self._appendix(scan_data, findings))

        parts.append(r"\end{document}")

        return "\n\n".join(parts)

    def _preamble(self, config: ReportConfig) -> str:
        """Document preamble with packages and styling"""
        return r"""\documentclass[11pt,a4paper]{report}

% Packages
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\usepackage[margin=2.5cm]{geometry}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{hyperref}
\usepackage{listings}
\usepackage{fancyhdr}
\usepackage{titlesec}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{enumitem}
\usepackage{tcolorbox}
\usepackage{tikz}

% Colors
\definecolor{criticalcolor}{RGB}{220, 38, 38}
\definecolor{highcolor}{RGB}{234, 88, 12}
\definecolor{mediumcolor}{RGB}{217, 119, 6}
\definecolor{lowcolor}{RGB}{8, 145, 178}
\definecolor{infocolor}{RGB}{107, 114, 128}
\definecolor{accentcolor}{RGB}{34, 211, 238}
\definecolor{darkbg}{RGB}{10, 10, 10}
\definecolor{codebg}{RGB}{30, 30, 30}

% Hyperref setup
\hypersetup{
    colorlinks=true,
    linkcolor=accentcolor,
    urlcolor=accentcolor,
    citecolor=accentcolor,
    pdftitle={""" + self._escape_latex(config.title) + r"""},
    pdfauthor={""" + self._escape_latex(config.author) + r"""}
}

% Code listings
\lstset{
    backgroundcolor=\color{codebg},
    basicstyle=\ttfamily\small\color{white},
    breaklines=true,
    frame=single,
    rulecolor=\color{gray},
    numbers=left,
    numberstyle=\tiny\color{gray},
    showstringspaces=false,
    tabsize=2
}

% Headers and footers
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\textcolor{gray}{""" + self._escape_latex(config.classification) + r"""}}
\fancyhead[R]{\small\textcolor{gray}{\leftmark}}
\fancyfoot[C]{\small\textcolor{gray}{Page \thepage}}
\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.5pt}

% Section styling
\titleformat{\chapter}[display]
    {\normalfont\huge\bfseries}
    {\chaptertitlename\ \thechapter}{20pt}{\Huge}
\titleformat{\section}
    {\normalfont\Large\bfseries}
    {\thesection}{1em}{}
\titleformat{\subsection}
    {\normalfont\large\bfseries}
    {\thesubsection}{1em}{}

% Severity box
\newtcolorbox{severitybox}[2][]{
    colback=#2!5,
    colframe=#2,
    fonttitle=\bfseries,
    title=#1,
    arc=2mm,
    boxrule=1pt
}

% Finding box
\newtcolorbox{findingbox}[1][]{
    colback=darkbg!5,
    colframe=gray,
    fonttitle=\bfseries,
    title=#1,
    arc=2mm,
    boxrule=0.5pt
}

\begin{document}
"""

    def _title_page(self, scan_data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate title page"""
        target = scan_data.get('target', 'Unknown Target')
        scan_date = scan_data.get('date', datetime.now().strftime('%Y-%m-%d'))

        return r"""
\begin{titlepage}
    \centering
    \vspace*{2cm}

    {\Huge\bfseries """ + self._escape_latex(config.title) + r"""\par}

    \vspace{1cm}

    {\Large\textcolor{gray}{Security Assessment}\par}

    \vspace{2cm}

    \begin{tcolorbox}[colback=darkbg!5,colframe=accentcolor,width=0.8\textwidth]
        \centering
        {\large\textbf{Target:} """ + self._escape_latex(target) + r"""}\par
        \vspace{0.5cm}
        {\textbf{Date:} """ + self._escape_latex(scan_date) + r"""}
    \end{tcolorbox}

    \vfill

    {\large """ + self._escape_latex(config.author) + r"""\par}
    """ + (r"{\large " + self._escape_latex(config.company) + r"\par}" if config.company else "") + r"""

    \vspace{1cm}

    {\small\textcolor{criticalcolor}{\textbf{""" + self._escape_latex(config.classification) + r"""}}\par}

\end{titlepage}
"""

    def _executive_summary(self, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generate executive summary"""

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        total = len(findings)
        critical_high = severity_counts['critical'] + severity_counts['high']

        # Risk assessment
        if severity_counts['critical'] > 0:
            risk_level = "Critical"
            risk_color = "criticalcolor"
        elif severity_counts['high'] > 2:
            risk_level = "High"
            risk_color = "highcolor"
        elif severity_counts['high'] > 0 or severity_counts['medium'] > 3:
            risk_level = "Medium"
            risk_color = "mediumcolor"
        else:
            risk_level = "Low"
            risk_color = "lowcolor"

        return r"""
\chapter{Executive Summary}

\section{Overview}

This report presents the findings of a security assessment conducted on
\textbf{""" + self._escape_latex(scan_data.get('target', 'the target')) + r"""}.

The assessment identified \textbf{""" + str(total) + r""" vulnerabilities},
including \textbf{""" + str(critical_high) + r""" critical/high severity issues}
requiring immediate attention.

\section{Risk Assessment}

\begin{center}
\begin{tikzpicture}
    \node[draw=none, fill=""" + risk_color + r"""!20, minimum width=6cm, minimum height=2cm,
          rounded corners, font=\Large\bfseries]
          {\textcolor{""" + risk_color + r"""}{Overall Risk: """ + risk_level + r"""}};
\end{tikzpicture}
\end{center}

\section{Findings Summary}

\begin{center}
\begin{tabular}{l r}
\toprule
\textbf{Severity} & \textbf{Count} \\
\midrule
\textcolor{criticalcolor}{\textbf{Critical}} & """ + str(severity_counts['critical']) + r""" \\
\textcolor{highcolor}{\textbf{High}} & """ + str(severity_counts['high']) + r""" \\
\textcolor{mediumcolor}{\textbf{Medium}} & """ + str(severity_counts['medium']) + r""" \\
\textcolor{lowcolor}{\textbf{Low}} & """ + str(severity_counts['low']) + r""" \\
\textcolor{infocolor}{Info} & """ + str(severity_counts['info']) + r""" \\
\midrule
\textbf{Total} & \textbf{""" + str(total) + r"""} \\
\bottomrule
\end{tabular}
\end{center}

\section{Key Recommendations}

\begin{enumerate}
    \item Address all critical and high severity vulnerabilities immediately
    \item Implement input validation and output encoding
    \item Review access control mechanisms
    \item Enable security headers and HTTPS
    \item Conduct regular security assessments
\end{enumerate}
"""

    def _findings_section(self, findings: List[Dict[str, Any]], config: ReportConfig) -> str:
        """Generate detailed findings section"""

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))

        parts = [r"\chapter{Vulnerability Findings}"]

        for i, finding in enumerate(sorted_findings, 1):
            parts.append(self._finding_entry(finding, i, config))

        return "\n\n".join(parts)

    def _finding_entry(self, finding: Dict[str, Any], index: int, config: ReportConfig) -> str:
        """Generate a single finding entry"""

        severity = finding.get('severity', 'info').lower()
        color = self.SEVERITY_COLORS.get(severity, 'infocolor')
        title = finding.get('title', f'Finding {index}')

        entry = r"""
\section{""" + self._escape_latex(title) + r"""}

\begin{severitybox}[Severity: """ + severity.upper() + r"""]{""" + color + r"""}

\textbf{Category:} """ + self._escape_latex(finding.get('category', 'Unknown')) + r"""

\textbf{Affected URL:} \url{""" + self._escape_latex(finding.get('url', finding.get('affected_url', 'N/A'))) + r"""}

""" + (r"\textbf{Affected Parameter:} \texttt{" + self._escape_latex(finding.get('affected_parameter', '')) + r"}" if finding.get('affected_parameter') else "") + r"""

\end{severitybox}

\subsection{Description}

""" + self._escape_latex(finding.get('description', 'No description available.')) + r"""
"""

        if config.include_technical_details and finding.get('payload'):
            entry += r"""
\subsection{Proof of Concept}

\begin{lstlisting}[language=bash]
""" + finding.get('payload', '') + r"""
\end{lstlisting}
"""

        if finding.get('evidence'):
            entry += r"""
\subsection{Evidence}

""" + self._escape_latex(finding.get('evidence', '')) + r"""
"""

        if config.include_remediation and finding.get('remediation'):
            entry += r"""
\subsection{Remediation}

""" + self._escape_latex(finding.get('remediation', '')) + r"""
"""

        if finding.get('references'):
            refs = finding.get('references', [])
            if refs:
                entry += r"""
\subsection{References}

\begin{itemize}
"""
                for ref in refs:
                    entry += r"    \item \url{" + self._escape_latex(ref) + r"}" + "\n"
                entry += r"\end{itemize}"

        if finding.get('cwe_id'):
            entry += r"""

\textbf{CWE:} """ + self._escape_latex(finding.get('cwe_id', ''))

        if finding.get('owasp_category'):
            entry += r"""

\textbf{OWASP:} """ + self._escape_latex(finding.get('owasp_category', ''))

        return entry

    def _appendix(self, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generate appendix with technical details"""

        return r"""
\chapter{Appendix}

\section{Scan Information}

\begin{tabular}{l l}
\toprule
\textbf{Property} & \textbf{Value} \\
\midrule
Scan ID & \texttt{""" + self._escape_latex(scan_data.get('scan_id', 'N/A')) + r"""} \\
Target & """ + self._escape_latex(scan_data.get('target', 'N/A')) + r""" \\
Mode & """ + self._escape_latex(scan_data.get('mode', 'N/A')) + r""" \\
Depth & """ + self._escape_latex(scan_data.get('depth', 'N/A')) + r""" \\
Started & """ + self._escape_latex(scan_data.get('started_at', 'N/A')) + r""" \\
Completed & """ + self._escape_latex(scan_data.get('completed_at', 'N/A')) + r""" \\
\bottomrule
\end{tabular}

\section{Methodology}

The security assessment was conducted using the All-Hack automated penetration testing platform.
The following phases were executed:

\begin{enumerate}
    \item \textbf{Reconnaissance:} Target enumeration, technology detection
    \item \textbf{Scanning:} Vulnerability scanning across OWASP Top 10 categories
    \item \textbf{Exploitation:} Proof of concept validation
    \item \textbf{Analysis:} AI-powered vulnerability analysis
    \item \textbf{Reporting:} Automated report generation
\end{enumerate}

\section{Disclaimer}

This report is provided for authorized security testing purposes only.
The findings represent the state of the target system at the time of assessment.
The authors are not responsible for any misuse of the information contained herein.
"""

    def _escape_latex(self, text: str) -> str:
        """Escape special LaTeX characters"""
        if not text:
            return ""

        # Characters that need escaping in LaTeX
        replacements = {
            '\\': r'\textbackslash{}',
            '&': r'\&',
            '%': r'\%',
            '$': r'\$',
            '#': r'\#',
            '_': r'\_',
            '{': r'\{',
            '}': r'\}',
            '~': r'\textasciitilde{}',
            '^': r'\textasciicircum{}',
            '<': r'\textless{}',
            '>': r'\textgreater{}',
        }

        text = str(text)
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)

        return text


# API Functions
def generate_latex_report(
    scan_id: str,
    target: str,
    findings: List[Dict[str, Any]],
    config: Dict[str, Any] = None,
    output_dir: str = None
) -> Dict[str, Any]:
    """
    Generate a LaTeX report for scan findings.

    Args:
        scan_id: Unique scan identifier
        target: Target URL
        findings: List of vulnerability findings
        config: Optional report configuration
        output_dir: Output directory for report files

    Returns:
        Dict with paths to generated files
    """
    generator = LaTeXReportGenerator(output_dir)

    report_config = ReportConfig(
        title=config.get('title', 'Penetration Testing Report') if config else 'Penetration Testing Report',
        author=config.get('author', 'All-Hack Security Scanner') if config else 'All-Hack Security Scanner',
        company=config.get('company', '') if config else '',
        classification=config.get('classification', 'CONFIDENTIAL') if config else 'CONFIDENTIAL',
    )

    scan_data = {
        'scan_id': scan_id,
        'target': target,
        'date': datetime.now().strftime('%Y-%m-%d'),
        'started_at': datetime.now().isoformat(),
        'completed_at': datetime.now().isoformat(),
        'mode': config.get('mode', 'automated') if config else 'automated',
        'depth': config.get('depth', 'balanced') if config else 'balanced',
    }

    tex_path = generator.generate_report(scan_data, findings, report_config)

    result = {
        'tex_path': tex_path,
        'pdf_path': None,
    }

    # Try to compile PDF
    pdf_path = generator.compile_pdf(tex_path)
    if pdf_path:
        result['pdf_path'] = pdf_path

    return result

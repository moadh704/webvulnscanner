# ── core/reporter.py ─────────────────────────────────────────────────────────

import os
import json
from datetime import datetime

import config


class Reporter:
    """
    Final stage of the WebVulnScanner pipeline.
    Generates two output formats:
    - HTML report: styled, self-contained, human-readable (Jinja2)
    - JSON report: machine-readable, CI/CD ready
    """

    def __init__(self, findings: list, output_dir: str,
                 report_name: str = None):
        self.findings    = findings
        self.output_dir  = output_dir
        self.report_name = report_name
        self.scan_date   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self) -> dict:
        """Generate both HTML and JSON reports. Returns output file paths."""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix    = self.report_name if self.report_name else f"report_{timestamp}"
        html_path = os.path.join(self.output_dir, f"{prefix}.html")
        json_path = os.path.join(self.output_dir, f"{prefix}.json")

        self._generate_html(html_path)
        self._generate_json(json_path)

        return {'html': html_path, 'json': json_path}

    # ── HTML Report ───────────────────────────────────────────────────────────

    def _generate_html(self, path: str):
        """Render Jinja2 template with findings data."""
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape

            template_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'templates'
            )
            env      = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(['html'])
            )
            template = env.get_template('report.html')

            html = template.render(
                findings   = self.findings,
                target_url = config.TARGET_URL,
                source_dir = config.SOURCE_DIR,
                scan_date  = self.scan_date,
                ai_provider= config.AI_PROVIDER,
            )

            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)

            print(f"  [Reporter] HTML report: {path}")

        except Exception as e:
            print(f"  [Reporter] HTML generation failed: {e}")

    # ── JSON Report ───────────────────────────────────────────────────────────

    def _generate_json(self, path: str):
        """Export findings as structured JSON."""
        try:
            # Build clean JSON-serializable report
            report = {
                'scan_info': {
                    'tool'       : 'WebVulnScanner v1.0',
                    'date'       : self.scan_date,
                    'target_url' : config.TARGET_URL,
                    'source_dir' : config.SOURCE_DIR,
                    'ai_provider': config.AI_PROVIDER,
                    'total'      : len(self.findings),
                    'summary'    : {
                        'critical': sum(1 for f in self.findings
                                       if f.get('severity') == 'Critical'),
                        'high'    : sum(1 for f in self.findings
                                       if f.get('severity') == 'High'),
                        'medium'  : sum(1 for f in self.findings
                                       if f.get('severity') == 'Medium'),
                        'low'     : sum(1 for f in self.findings
                                       if f.get('severity') == 'Low'),
                        'type1'   : sum(1 for f in self.findings
                                       if f.get('finding_type') == 1),
                        'type2'   : sum(1 for f in self.findings
                                       if f.get('finding_type') == 2),
                        'type3'   : sum(1 for f in self.findings
                                       if f.get('finding_type') == 3),
                    }
                },
                'findings': [self._clean_finding(f) for f in self.findings]
            }

            with open(path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)

            print(f"  [Reporter] JSON report: {path}")

        except Exception as e:
            print(f"  [Reporter] JSON generation failed: {e}")

    def _clean_finding(self, finding: dict) -> dict:
        """Return a clean JSON-serializable finding dict."""
        return {
            'type'             : finding.get('type', ''),
            'owasp'            : finding.get('owasp', ''),
            'url'              : finding.get('url', ''),
            'parameter'        : finding.get('parameter', ''),
            'finding_type'     : finding.get('finding_type', 3),
            'confidence'       : finding.get('confidence', 0.65),
            'severity'         : finding.get('severity', 'Medium'),
            'technique'        : finding.get('technique', ''),
            'payload'          : finding.get('payload', ''),
            'evidence_static'  : finding.get('evidence_static', ''),
            'evidence_dynamic' : finding.get('evidence_dynamic', ''),
            'ai_note'          : finding.get('ai_note', ''),
            'remediation'      : finding.get('remediation', ''),
            'status'           : finding.get('status', 'confirmed'),
        }
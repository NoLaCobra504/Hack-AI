import os
from datetime import datetime

def ensure_final_reports_dir():
    """Ensure the Final_Reports directory exists."""
    final_reports_dir = "Final_Reports"
    if not os.path.exists(final_reports_dir):
        os.makedirs(final_reports_dir)
        print(f"[+] Created Final_Reports directory: {final_reports_dir}")
    return final_reports_dir

def get_report_name(cve_id=None, base_dir='Final_Reports'):
    """Generate a report filename based on CVE or generic if not provided."""
    # Ensure the Final_Reports directory exists
    ensure_final_reports_dir()
    
    now = datetime.now().strftime('%Y-%m-%d_%H%M')
    if cve_id:
        name = f"{cve_id}_report_{now}.md"
    else:
        name = f"final_report_{now}.md"
    return os.path.join(base_dir, name)


def init_report(report_path, target, operator=None, cve_id=None):
    """Create the initial report with cover info if it doesn't exist."""
    # Ensure the Final_Reports directory exists
    ensure_final_reports_dir()
    
    if not os.path.exists(report_path):
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# HackingAI - AI-Powered Ethical Hacking Report\n\n")
            if cve_id:
                f.write(f"**CVE:** `{cve_id}`  \n")
            f.write(f"**Target:** `{target}`  \n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
            if operator:
                f.write(f"**Operator:** {operator}  \n")
            f.write(f"**AI-Powered:** Yes  \n")
            f.write(f"\n---\n\n")


def append_section(report_path, section_title, methodology, commands, findings, notable, recommendations, raw_output=None):
    """Append a new section to the report."""
    # Ensure the Final_Reports directory exists
    ensure_final_reports_dir()
    
    with open(report_path, 'a', encoding='utf-8') as f:
        f.write(f"## {section_title}\n\n")
        f.write(f"### Methodology\n{methodology}\n\n")
        if commands:
            f.write(f"### Commands/Queries\n")
            f.write(f"```shell\n" + '\n'.join(commands) + "\n```\n\n")
        if findings:
            f.write(f"### Findings\n")
            if isinstance(findings, dict):
                for k, v in findings.items():
                    f.write(f"- **{k}:** {v}\n")
            elif isinstance(findings, list):
                for item in findings:
                    f.write(f"- {item}\n")
            else:
                f.write(f"- {findings}\n")
            f.write(f"\n")
        if notable:
            f.write(f"### Notable Observations\n")
            for n in notable:
                f.write(f"- {n}\n")
            f.write(f"\n")
        if recommendations:
            f.write(f"### Recommendations\n")
            for r in recommendations:
                f.write(f"- {r}\n")
            f.write(f"\n")
        if raw_output:
            f.write(f"### Raw Output\n")
            f.write(f"```json\n")
            import json
            f.write(json.dumps(raw_output, indent=2))
            f.write(f"\n```")
        f.write(f"\n---\n\n") 
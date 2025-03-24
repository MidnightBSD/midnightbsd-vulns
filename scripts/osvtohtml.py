#!/usr/bin/python3
#
#  Copyright 2023 Lucas Holt
#  Licensed under the Apache License, Version 2.0.
#  See http://www.apache.org/licenses/LICENSE-2.0 for the full text.
"""
Usage:
    python osvtohtml.py /path/to/yaml > doc.html
"""
import sys
import os
import yaml
from datetime import datetime

CSS = """
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }
    h1 { color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 10px; }
    h2 { color: #34495e; margin-top: 30px; }
    h3 { color: #7f8c8d; }
    .severity { font-weight: bold; }
    .severity.critical { color: #c0392b; }
    .severity.high { color: #e74c3c; }
    .severity.medium { color: #f39c12; }
    .severity.low { color: #16a085; }
    .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    .dates { font-style: italic; }
    ul { padding-left: 20px; }
"""

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MidnightBSD Advisory: {id} {summary}</title>
  <style>{css}</style>
</head>
<body>
<h1>{id}: {summary}</h1>

<div class="summary">
  <p><strong>Severity:</strong> <span class="severity {severity_class}">{severity}</span></p>
  <p><strong>Affected Package:</strong> {package}</p>
  <p><strong>Summary:</strong> {summary}</p>
</div>

<h2>Description</h2>
<p>{description}</p>

<h2>Affected Versions</h2>
{affected_versions}

<h2>Recommendations</h2>
<p>{recommendations}</p>

<h2>References</h2>
<ul>
{references}
</ul>

<h2>Additional Information</h2>
<p><strong>Aliases:</strong> {aliases}</p>
<p class="dates">
Published: {published}<br>
Last Modified: {modified}
</p>
</body>
</html>
"""


def format_date(date_string):
    date = datetime.fromisoformat(date_string.replace("Z", "+00:00"))
    return date.strftime("%B %d, %Y")

def parse_cvss_score(score):
    if score.startswith("CVSS:"):
        parts = score.split("/")
        base_score = parts[0].split(":")[1]
        return float(base_score)
    return None

def get_severity_class(severity):
    if not severity or not isinstance(severity, list) or len(severity) == 0:
        return "unknown"

    highest_score = 0
    for sev in severity:
        if sev['type'] in ['CVSS_V2', 'CVSS_V3', 'CVSS_V4']:
            score = parse_cvss_score(sev['score'])
            if score is not None:
                highest_score = max(highest_score, score)
        elif sev['type'] == 'Ubuntu':
            ubuntu_scores = {
                'negligible': 0,
                'low': 3,
                'medium': 5,
                'high': 7,
                'critical': 9
            }
            score = ubuntu_scores.get(sev['score'].lower(), 0)
            highest_score = max(highest_score, score)
    if highest_score >= 9.0:
        return "critical"
    elif highest_score >= 7.0:
        return "high"
    elif highest_score >= 4.0:
        return "medium"
    elif highest_score > 0:
        return "low"
    else:
        return "unknown"

def format_severity(severity):
    if not severity or not isinstance(severity, list) or len(severity) == 0:
        return "Unknown"

    severity_strings = []
    for sev in severity:
        severity_strings.append(f"{sev['type']}: {sev['score']}")

    return ", ".join(severity_strings)

def process_yaml_file(yaml_file_path, output_dir):
    with open(yaml_file_path, 'r') as file:
        vuln = yaml.safe_load(file)

    # Generate affected versions HTML
    affected_versions = ""
    package = "Unknown"
    for affected in vuln.get("affected", []):
        package = affected.get("package", {}).get("name", "Unknown")
        affected_versions += f"<h3>{package}</h3>"
        affected_versions += "<ul>"
        for version_range in affected.get("ranges", []):
            type = version_range.get("type", "Unknown")
            if type == "SEMVER":
                events = version_range.get("events", [])
                introduced = next((e["value"] for e in events if e["introduced"]), "Unknown")
                fixed = next((e["value"] for e in events if e.get("fixed")), "Not Fixed")
                affected_versions += f"<li>Introduced: {introduced}, Fixed: {fixed}</li>"
            elif type == "GIT":
                events = version_range.get("events", [])
                introduced = next((e["value"] for e in events if e["introduced"]), "Unknown")
                fixed = next((e["value"] for e in events if e.get("fixed")), "Not Fixed")
                affected_versions += f"<li>Introduced commit: {introduced}, Fixed commit: {fixed}</li>"
        affected_versions += "</ul>"

        versions = affected.get("versions", [])
        if versions:
            affected_versions += "<p>Specific versions:</p><ul>"
            for version in versions:
                affected_versions += f"<li>{version}</li>"
            affected_versions += "</ul>"

    references = "\n".join(f'<li><a href="{u["url"]}">{u["url"]}</a></li>' for u in vuln["references"])
    aliases = vuln.get("aliases", [])
    if isinstance(aliases, list):
        aliases = ", ".join(str(x) for x in aliases)
    elif aliases:
        aliases = str(aliases)
    else:
        aliases = "None"

    severity = vuln.get("severity", [])
    severity_formatted = format_severity(severity)
    severity_class = get_severity_class(severity)

    html_content = TEMPLATE.format(
        css=CSS,
        id=vuln["id"],
        summary=vuln["summary"],
        severity=severity_formatted,
        severity_class=severity_class,
        package=package,
        description=vuln["details"],
        affected_versions=affected_versions,
        recommendations=vuln.get("recommendations", "No specific recommendations provided."),
        modified=format_date(vuln["modified"]),
        published=format_date(vuln["published"]),
        references=references,
        aliases=aliases
    )

    # Generate output file name
    base_name = os.path.splitext(os.path.basename(yaml_file_path))[0]
    output_file = os.path.join(output_dir, f"{base_name}.html")

    # Write HTML content to file
    with open(output_file, 'w') as file:
        file.write(html_content)

    print(f"Generated: {output_file}")


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 osvtohtml.py /path/to/yaml/directory [/path/to/output/directory]")
        sys.exit(1)

    input_directory = sys.argv[1]
    if not os.path.isdir(input_directory):
        print(f"Error: {input_directory} is not a valid directory")
        sys.exit(1)

    if len(sys.argv) == 3:
        output_directory = sys.argv[2]
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    else:
        output_directory = input_directory

    print(f"Input directory: {input_directory}")
    print(f"Output directory: {output_directory}")

    yaml_files = [f for f in os.listdir(input_directory) if f.endswith(('.yaml', '.yml'))]
    print(f"Found {len(yaml_files)} YAML files")

    if not yaml_files:
        print("No YAML files found in the input directory")
        sys.exit(1)

    for filename in yaml_files:
        yaml_file_path = os.path.join(input_directory, filename)
        print(f"Processing: {yaml_file_path}")
        try:
            process_yaml_file(yaml_file_path, output_directory)
        except Exception as e:
            print(f"Error processing {filename}: {str(e)}")
if __name__ == "__main__":
    main()
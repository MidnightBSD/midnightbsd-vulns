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

def get_severity_class(severity):
    severity = severity.lower()
    if severity == "critical":
        return "critical"
    elif severity == "high":
        return "high"
    elif severity == "medium":
        return "medium"
    else:
        return "low"

if len(sys.argv) == 1:
    sys.exit(-1)
else:
    filename = sys.argv[1]

vuln = yaml.load(open(filename, 'r'), Loader=yaml.FullLoader)

# Generate affected versions HTML
affected_versions = ""
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
aliases = ", ".join(str(x) for x in vuln["aliases"])

severity = vuln.get("severity", "Unknown")
severity_class = get_severity_class(severity)


sys.stdout.write(TEMPLATE.format(
    css=CSS,
    id=vuln["id"],
    summary=vuln["summary"],
    severity=severity,
    severity_class=severity_class,
    package=package,
    description=vuln["details"],
    affected_versions=affected_versions,
    recommendations=vuln.get("recommendations", "No specific recommendations provided."),
    modified=format_date(vuln["modified"]),
    published=format_date(vuln["published"]),
    references=references,
    aliases=aliases
))
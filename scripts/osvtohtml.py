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

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MidnightBSD Advisory: {id} {summary}</title>
</head>
<body>
<h1>{id} {summary}</h1>
<p>{description}</p>

<p>Aliases: {aliases}</p>

<p>
Modified: {modified}<br>
Published: {published}
</p>

<p>References</p>
<p>{references}</p>
</body>
</html>
"""

if len(sys.argv) == 1:
    sys.exit(-1)
else:
    filename = sys.argv[1]

vuln = yaml.load(open(filename, 'r'), Loader=yaml.FullLoader)
references = '<br>'.join(str(u["url"]) for u in vuln["references"])
aliases = ','.join(str(x) for x in vuln["aliases"])
sys.stdout.write(TEMPLATE.format(id=vuln["id"], summary=vuln["summary"], description=vuln["details"], modified=vuln["modified"], published=vuln["published"], references=references, aliases=aliases))

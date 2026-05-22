# MidnightBSD Vulnerability Advisories

This repository contains security advisories for the MidnightBSD operating system in OSV (Open Source Vulnerability) YAML format, as well as scripts to convert them into HTML for publication.

## Directory Structure

* **`vulns/midnightbsd/`**: This directory contains all the security advisory YAML files. Each file represents a single vulnerability and is named using the pattern `MNBSD-YYYY-ID.yaml` (e.g., `MNBSD-2026-1.yaml`).
* **`scripts/`**: Contains utility scripts, such as `osvtohtml.py`, which is used to generate HTML documents from the YAML advisories.
* **`latest-id.txt`**: A plain text file located at the root of the repository that keeps track of the latest assigned ID for the current year (e.g., `2026-14`). This helps ensure that no vulnerability IDs overlap.

## Process for Creating New Vulnerabilities

To document a new vulnerability, follow these steps:

1. **Determine the Next ID**: Check the `latest-id.txt` file at the root of the repository to find the next available ID for the current year. For example, if it says `2026-14`, your new advisory should be `2026-15`.
2. **Create the YAML Advisory**: Create a new file in the `vulns/midnightbsd/` directory named `MNBSD-YYYY-ID.yaml`. Use the OSV schema format. You can copy an existing file (like `MNBSD-2025-6.yaml` or `MNBSD-2026-0.yaml`) as a template and update the following fields:
   * `id`: The unique identifier (e.g., `MNBSD-2026-15`).
   * `summary`: A brief description of the vulnerability.
   * `details`: A comprehensive explanation of the vulnerability, its impact, and potential workarounds.
   * `affected`: Specify the affected package (e.g., `kernel`, `openssl`), ecosystem (`MidnightBSD`), and the range of affected and fixed versions.
   * `references`: Links to relevant FreeBSD advisories, CVE records, or other documentation.
   * `aliases`: Include any corresponding CVE IDs (e.g., `CVE-2026-XXXX`).
   * `modified` / `published`: Timestamp of the advisory publication/modification (in ISO 8601 format like `"2026-05-21T12:00:00Z"`).
3. **Update `latest-id.txt`**: Update the root `latest-id.txt` file to reflect your newly assigned ID.

## Generating HTML Documents

Once you have created or updated the YAML advisories, you can generate formatted HTML documents using the included Python script.

Run the following command from the root of the repository:

```bash
python3 scripts/osvtohtml.py vulns/midnightbsd
```

This will parse all YAML files in the `vulns/midnightbsd` directory and generate a corresponding HTML file (e.g., `MNBSD-2026-1.html`) right next to each YAML file.

If you wish to output the generated HTML files to a different directory, provide a second argument to the script:

```bash
python3 scripts/osvtohtml.py vulns/midnightbsd /path/to/output/directory
```

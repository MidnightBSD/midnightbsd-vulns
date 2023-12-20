# MidnightBSD Security Advisory Database
MidnightBSD Security Advisories - Vulnerability Disclosure

Advisories live in the [vulns](vulns/) directory and use a YAML encoding of the
[OSV format](https://ossf.github.io/osv-schema/).

This repository is for MidnightBSD base system and mport package manager security vulnerabilities only.

This is unrelated to the MidnightBSD Security Advisory webapp which displays CVEs and is integrated with the mport package manager and advisory.pl perl scripts for checking packages installed outside of the base system.

## Contributing advisories

### Making a pull request

Existing entries can be edited by simply creating a pull request.

To introduce a new entry, create a pull request with a new file that has a name matching MNBSD-<latest-id.txt + 1>-<anything>.yaml.

Increment the file `latest-id.txt` in your pull request.

MidnightBSD operating system vulnerabilities for the base system should
be put in the `vulns/midnightbsd` directory.

mport package manager security advisories should be put in the `vulns/mport` directory.

Ecosystem entries should be MidnightBSD or mport

### Triage process

Vulnerabilities should be pulled from a source like Github or the [NVD CVE](https://nvd.nist.gov/vuln/data-feeds) feeds.
These will be properly vetted and approved.

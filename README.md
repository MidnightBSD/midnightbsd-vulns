# MidnightBSD Security Advisory Database
MidnightBSD Security Advisories - Vulnerability Disclosure

Advisories live in the [vulns](vulns/) directory and use a YAML encoding of the
[OSV format](https://ossf.github.io/osv-schema/).

## Contributing advisories

### Making a pull request

Existing entries can be edited by simply creating a pull request.

To introduce a new entry, create a pull request with a new file that has a name matching MNBSD-<latest-id.txt + 1>-<anything>.yaml.

Increment the file `latest-id.txt` in your pull request.

MidnightBSD operating system vulnerabilities for the base system should
be put in the `vulns/midnightbsd` directory.

mport package manager security advisories should be put in the `vulns/mport` directory.

### Triage process

Vulnerabilities should be pulled from a source like Github or the [NVD CVE](https://nvd.nist.gov/vuln/data-feeds) feeds.
These will be properly vetted, and approved.

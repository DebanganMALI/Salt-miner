# Security Policy

## Supported versions

Saltminer is under active development. Security fixes are applied to the most
recent release published on [PyPI](https://pypi.org/project/saltminer/) and to
the latest [GitHub release](https://github.com/DebanganMALI/Salt-miner/releases).
Please make sure you are on the newest version before reporting an issue.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

If you discover a security vulnerability in Saltminer, please report it
**privately** rather than opening a public issue.

- **Email:** debanganmali.social@yahoo.com

Please include, where possible:

- a clear description of the issue and its potential impact,
- the steps or the specific input needed to reproduce it,
- the affected version and platform.

I aim to acknowledge a report within 72 hours and to share a resolution or
mitigation timeline once the issue has been triaged.

## Scope

Saltminer runs fully offline: it performs no network, filesystem, or process
access, and its only untrusted input is the hash string it is asked to analyse.
Reports are especially valued for:

- a crash, panic, or hang triggered by a crafted input string,
- an incorrect or misleading audit verdict that could lead a user to treat an
  insecure hash as secure,
- any memory-safety issue in the Rust core or the Python (PyO3) bindings.

## Out of scope

- Vulnerabilities in third-party dependencies — please report these to the
  upstream project; Saltminer will pick up the fix on the next release.
- The cryptographic strength of the hashes themselves. Saltminer identifies and
  rates hashes; it does not create, store, or transmit them.

## Disclosure

Please allow a reasonable period for a fix to be prepared before any public
disclosure. Reporters who wish to be credited will be acknowledged in the
release notes.

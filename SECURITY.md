<!--
SPDX-FileCopyrightText: 2026 Gianluca Boiano
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# Security Policy

libopencie-pkcs11 is a volunteer-maintained, non-commercial open-source project. Reports are handled on a best-effort basis by a single maintainer.

## Supported versions

Only the [latest release](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) receives security fixes. Please reproduce the problem on the latest release before reporting.

## Reporting a vulnerability

Please **do not** open a public issue, pull request or discussion for a suspected vulnerability.

Use GitHub private vulnerability reporting instead:

1. Go to the [Security tab](https://github.com/M0Rf30/opencie-pkcs11/security) of this repository.
2. Choose **Report a vulnerability** (or open [a new private advisory](https://github.com/M0Rf30/opencie-pkcs11/security/advisories/new) directly).

Helpful details:

- The affected library version and platform (Linux/Windows/macOS/Android), the reader model, and the consumer (OpenCIE, a browser via PKCS#11, a language binding, your own code).
- A clear description of the issue and its impact.
- Steps to reproduce, or a proof of concept. Use synthetic data only: never attach real PINs, PUKs, CANs, card data, certificates or personal documents.
- Any suggested fix or mitigation.

## What to expect

- Acknowledgement within **7 days**.
- A follow-up with an assessment and, for valid reports, a fix and release plan. There is no fixed fix timeline: this is a volunteer project and fixes are made on a best-effort basis.
- Coordinated disclosure: please give me a reasonable time to ship a fix before publishing details. Fixed issues are published as a GitHub security advisory, with credit if you want it.

## Scope

In scope:

- PIN, PUK and CAN handling: buffers, wiping, logging, retry counters.
- The PKCS#11 interface, the `cie_*` extension API and its ABI (anything a consumer can trigger through them).
- Card communication: APDU parsing, secure messaging, PACE, card/reader detection.
- Signature creation and verification (PAdES, CAdES, XAdES, PKCS#7/CMS), timestamping and certificate/revocation checks.
- Release artifacts: binaries, `SHA256SUMS`, SBOM and build provenance.

Out of scope:

- Vulnerabilities in third-party dependencies with no demonstrable impact on the library (report them upstream).
- Attacks that require malware already running with the user's privileges, or a compromised PC/SC daemon or reader driver.
- Flaws in the CIE card itself or in the Italian eID infrastructure.
- Denial of service through unrealistic inputs, and issues in unsupported or old versions.

## Verifying releases

Each release ships a CycloneDX software bill of materials (`libopencie-pkcs11-<tag>.cdx.json`), and every release asset has a signed [GitHub artifact attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) (SLSA build provenance). To check a download:

```bash
gh attestation verify libopencie-pkcs11-<tag>-linux-x86_64.so --repo M0Rf30/opencie-pkcs11
```

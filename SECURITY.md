# Security Policy

Agent Risk Analyzer (ARA) is a static security scanner for AI agent projects. Security reports, detector bypasses, and unsafe defaults are welcome.

## Supported Versions

ARA is currently in early alpha. Security fixes target the latest published version on PyPI and the `main` branch.

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a Vulnerability

Please do not open a public GitHub issue for a vulnerability that could help attackers bypass detections or hide risky agent behavior.

Report security issues by email:

```text
prnvlol@protonmail.com
```

Please include:

- A short description of the issue.
- A minimal vulnerable project, file, or code sample.
- The expected finding and the actual ARA result.
- The affected rule ID, detector, framework, or output format if known.
- Affected version or commit.

I will try to acknowledge reports within 72 hours and follow up with a fix plan or additional questions.

## Scope

In scope:

- False negatives for high-impact AI agent security risks.
- Crashes caused by scanning untrusted projects.
- Incorrect CI behavior that could allow risky code through.
- Unsafe defaults or documentation that could mislead users.
- Vulnerabilities in report generation or file handling.

Out of scope:

- Reports that require compromising GitHub, PyPI, or third-party services.
- Social engineering.
- False positives without a realistic impact or reproduction.
- Purely theoretical issues without a minimal sample.

## Safe Harbor

Good-faith research that avoids privacy violations, data destruction, service disruption, and unauthorized access is welcome. Please keep testing limited to your own repositories, local examples, and intentionally vulnerable samples.

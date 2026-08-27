# Security policy

## Supported version

The protected `main` branch is the only supported version. Deployments and
reports should identify the exact commit and the two framework pin commits.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** flow for this repository. Do
not open a public issue for suspected credential exposure, privilege
escalation, trust-policy bypass, or unsafe resource cleanup.

Include the affected commit, relevant workflow or policy path, reproduction
steps, and the potential AWS or guest impact. Maintainers aim to acknowledge
a report within three business days and provide an initial assessment within
seven business days.

If a credential may have been exposed, revoke or rotate it before sharing
diagnostic output. Never include AWS account identifiers, private keys,
certificate passwords, session tokens, or rendered IAM artifacts in a public
report.

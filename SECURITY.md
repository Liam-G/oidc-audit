# Security policy

## Supported versions

Until the first stable release, security fixes are provided on the latest
release only.

## Reporting a vulnerability

Please use GitHub's **Security** tab and select **Report a vulnerability** to
start a private advisory. Include the affected version, reproduction steps
using synthetic data, impact, and a suggested fix if available. Never include
live credentials, tokens, private keys, client secrets, or third-party exports.

Maintainers should acknowledge complete reports within seven days and
coordinate a fix and disclosure timeline with the reporter.

## Scope and data handling

Secret or private-key disclosure in output, unintended network access, unsafe
file handling, TLS validation bypass, and dependency compromise are in scope.
Local-file mode performs no network traffic. Version 0.2 URL mode performs
bounded GET requests only to issuer discovery, redirects, and the advertised
JWKS URI; it never authenticates or submits credentials. Input exports can
contain credentials and must be protected; `oidc-audit` reports only rule IDs,
structural JSON paths, and safe summaries.


# oidc-audit — plan

A configuration auditor for **your own** OAuth 2.0 / OpenID Connect setup.
It reads identity-provider metadata, published keys, and client configuration
exports, and reports deviations from current best practice (RFC 9700, the
OAuth 2.0 Security BCP) as text, JSON or SARIF — so it can gate a CI pipeline.

Sibling to `jwt-audit`: same conventions, same report formats, same exit codes.

Positioning: the existing tools are a Burp extension (needs Burp, not CI) or a
module inside a broader scanner. Nothing is a standalone, offline-first,
CI-friendly *config linter* for OIDC. That's the gap.

---

## 1. Project skeleton (copy from jwt-audit)

- [x] `pyproject.toml` — hatchling, `src/oidc_audit`, Python ≥3.10, ruff/mypy strict/pytest-cov ≥85 %
- [x] Copy over: `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
      `.github/workflows/ci.yml`, `.github/dependabot.yml`, `.gitignore`
- [x] Same exit codes: `0` clean, `2` findings, `1` config/operational error
- [x] Same report rules: never write secrets, client secrets or tokens into reports

Suggested layout:

```
src/oidc_audit/
  cli.py          # argparse, subcommands
  models.py       # Finding, Severity, Rule (copy/adapt from jwt-audit)
  reporting.py    # text / json / sarif (copy from jwt-audit, change tool name + rule ids)
  loaders/
    discovery.py  # .well-known/openid-configuration (file or URL)
    jwks.py       # JWKS (file or URL)
    keycloak.py   # Keycloak realm export JSON
    generic.py    # a small YAML/JSON schema for "any IdP" client lists
  rules/
    metadata.py   # rules on the discovery document
    keys.py       # rules on the JWKS
    clients.py    # rules on client registrations
    tokens.py     # rules on sample ID/access tokens (reuse jwt-audit inspector)
tests/
  fixtures/       # good + bad example configs, one per rule
```

## 2. Rules for v0.1 (all offline, no network traffic)

Every rule gets: an id (`OIDC-META-001`…), severity, one-line message,
remediation text, and the RFC section it comes from. The RFC reference is what
makes the tool credible — do this from day one.

### Discovery document (RFC 8414, RFC 9700)
- [x] `issuer` does not match the URL it was loaded from
- [x] any endpoint not on `https` (loopback excepted)
- [x] implicit flow advertised (`token`, `id_token token` in `response_types_supported`) — BCP says don't
- [x] `password` in `grant_types_supported` — BCP says must not be used
- [x] `code_challenge_methods_supported` missing, or contains `plain` without `S256`
- [x] `none` in `id_token_signing_alg_values_supported`
- [x] only symmetric (HS*) signing algorithms advertised
- [x] no PAR endpoint (RFC 9126) — info level only
- [x] `jwks_uri` missing or not https

### JWKS (RFC 7517 / 7518)
- [x] **private key material published** (`d`, `p`, `q`, `dp`, `dq`, `qi` present) — critical; this happens in real life
- [x] symmetric key (`kty: oct`) published — critical
- [x] RSA modulus < 2048 bits; EC on a non-standard curve
- [x] missing `kid`, duplicate `kid`s
- [x] missing `use` / `alg`

### Client registrations (Keycloak realm export first)
- [x] wildcard redirect URIs (`*`, `https://app.example/*`)
- [x] `http://` redirect URIs that are not loopback (RFC 8252 allows loopback for native apps)
- [x] `localhost` redirect URIs in a realm marked as production
- [x] public client without PKCE enforced (`pkce.code.challenge.method` not `S256`)
- [x] implicit flow enabled on a client
- [x] direct access grants (password grant) enabled
- [x] access-token lifetime above a threshold (configurable, default 15 min)
- [x] refresh-token rotation disabled for public clients
- [x] client secret present in the export → warn that the export itself is sensitive

### Sample tokens (optional input, reuse jwt-audit's inspector)
- [ ] missing `exp` / `iss` / `aud` / `azp`
- [ ] `alg` not in the IdP's advertised list
- [ ] lifetime longer than the configured threshold

## 3. CLI

```bash
# fully offline: files you exported from your own IdP
oidc-audit lint --discovery openid-configuration.json --jwks jwks.json
oidc-audit lint --keycloak realm-export.json --format sarif --output oidc.sarif

# fetch metadata + JWKS from your own IdP (read-only GETs, nothing else)
oidc-audit lint --issuer https://login.staging.example.test/realms/main

# compare two exports and fail only on regressions
oidc-audit diff --baseline realm-2026-09.json --current realm-export.json

# list rules with their RFC references
oidc-audit rules
```

Flags to carry over from jwt-audit's style: `--format text|json|sarif`,
`--output`, `--min-severity`, `--disable RULE_ID`, `--config oidc-audit.toml`.

## 4. Test lab

- [x] `examples/docker-compose.yml` with a local Keycloak and a deliberately
      misconfigured realm (`examples/bad-realm.json`) plus a clean one
      (`examples/good-realm.json`)
- [x] Unit tests use only fixture files — no network, same rule as jwt-audit
- [ ] One focused "bad" fixture per rule
- [x] One clean fixture that must produce zero findings (that's the false-positive test)

## 5. Milestones

| Version | Scope |
|---|---|
| 0.1 | Offline lint: discovery + JWKS + Keycloak export; text/JSON/SARIF; RFC refs |
| 0.2 | `--issuer` URL fetch (read-only), `diff` mode, `oidc-audit.toml` config |
| 0.3 | More export formats: Entra ID app manifest, Auth0 (`a0deploy` export), Okta, authentik |
| 0.4 | GitHub Action (`uses: Liam-G/oidc-audit@v0`) that uploads SARIF to code scanning |
| later | Shared `audit-core` package with jwt-audit (models + reporting), Debian packaging like jwt-audit |

Implemented through v0.2: read-only issuer fetching, regression-only diffing,
and `oidc-audit.toml` policy configuration are covered by offline tests.

## 6. Ideas / extras that would make it stand out

- **Diff mode is the killer feature.** Teams change IdP settings by hand in an admin UI;
  nobody notices when someone adds a wildcard redirect URI. Export nightly, diff
  against a committed baseline, fail CI on regressions.
- **Score + badge**: an "OIDC hygiene" score per realm, shields.io badge for READMEs.
- **Rule docs site**: one page per rule (why, RFC section, how to fix in Keycloak / Entra / Auth0).
  Good SEO, and it's what people link to.
- **`--explain RULE_ID`** prints the rule doc in the terminal.
- **Swiss/EU angle**: lots of public-sector and enterprise setups here run Keycloak.
  A blog post on webcracy.ch, "The 10 Keycloak settings we see wrong most often",
  launches the tool.
- **Cross-promote with jwt-audit**: each README links the other; a combined
  "auth audit" section in your GitHub profile README.

## 7. Before publishing

- [x] README with a 30-second quickstart using the bundled bad realm
- [ ] Screenshot of SARIF findings in GitHub code scanning
- [ ] CHANGELOG, tag `v0.1.0`, publish to PyPI
- [ ] Post: r/netsec, r/KeyCloak, Hacker News "Show HN"

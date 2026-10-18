# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 - Unreleased

- Add bounded, TLS-verified `lint --issuer` discovery and JWKS fetching.
- Add Keycloak `diff` mode that reports only newly introduced findings.
- Add stable per-client diff identities so export reordering is ignored.
- Add strict `[oidc-audit]` TOML policy configuration.
- Add `--fail-on` (default `low`) so info-level findings no longer fail CI.
- Report Keycloak's realm-wide implicit and password-grant metadata as
  info-level `OIDC-META-010` and `OIDC-META-011`, since only the realm export
  shows which clients enable them.
- Report every wildcard redirect URI, including `*` on its own and relative
  paths such as `/*`, which were previously skipped.
- Fetch and audit an `http://` JWKS on loopback issuers, and stop reporting it
  as `OIDC-META-009`.
- Ignore masked client secrets (`**********`) from admin-console exports.
- Apply `OIDC-CLIENT-004` only to clients with the browser (standard) flow.
- Lower `OIDC-META-006` to medium and cite OpenID Connect Discovery §3 for
  `OIDC-META-006` and `OIDC-META-007`.
- Fix the lab: Keycloak 26 imports a realm only from `<realm>-realm.json`.

## 0.1.0 - 2026-10-18

- Add fully offline discovery metadata, JWKS, and Keycloak realm checks.
- Add text, JSON, and SARIF output with stable rule IDs and RFC references.
- Add a local two-realm Keycloak lab and clean false-positive gate.
- Skip Keycloak-managed built-in clients by default, with an explicit opt-in.
- Emit GitHub-compatible numeric security severity scores in SARIF.
- Add a fresh Keycloak 26 realm-export regression fixture.


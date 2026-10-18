# oidc-audit

`oidc-audit` is an offline-first OAuth 2.0 and OpenID Connect configuration
linter. It audits provider metadata, published JSON Web Keys, and Keycloak
realm exports against current security guidance, then emits text, JSON, or
SARIF for humans and CI.

It does not include input values, client secrets, or key material in reports.
Local-file auditing remains fully offline; URL mode performs bounded,
read-only GET requests for discovery metadata and its advertised JWKS.

## Quick start

Requires Python 3.10 or newer.

```console
python -m pip install -e .
oidc-audit lint --keycloak examples/bad-realm.json
echo $?  # 2: findings were reported

oidc-audit lint --keycloak examples/good-realm.json
echo $?  # 0: clean
```

Audit several exports together and create a SARIF report:

```console
oidc-audit lint \
  --discovery tests/fixtures/bad-discovery.json \
  --expected-issuer https://login.example.test/realms/bad \
  --jwks tests/fixtures/bad-jwks.json \
  --keycloak examples/bad-realm.json \
  --format sarif --output oidc-audit.sarif
```

Audit a live issuer using only its public metadata and keys:

```console
oidc-audit lint --issuer https://login.example.test/realms/main
```

The issuer and its `jwks_uri` must use HTTPS. Plain HTTP is accepted only when
the issuer itself is on `localhost` or a loopback address.
TLS verification is always enabled. Responses are limited to 2 MiB and
redirects are bounded; HTTPS redirects cannot downgrade to HTTP.

Keycloak advertises the implicit response types and the password grant for
every realm, whatever its clients allow. For a Keycloak issuer (a path ending
in `/realms/<name>`) these are reported as info-level findings `OIDC-META-010`
and `OIDC-META-011`; audit a realm export with `--keycloak` to see which
clients actually enable them.

## Diff mode

Compare a committed Keycloak baseline with a new export and report only new
findings:

```console
oidc-audit diff \
  --baseline realm-baseline.json \
  --current realm-current.json \
  --format sarif --output oidc-regressions.sarif
```

Existing findings do not fail the diff. A newly introduced finding returns
exit code `2`. Client-based identities prevent array reordering from appearing
as configuration drift.

List every check and its normative reference:

```console
oidc-audit rules
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | No reported finding is at or above the `--fail-on` severity. |
| `1` | The command or input was invalid, or an operational error occurred. |
| `2` | At least one reported finding is at or above the `--fail-on` severity. |

`--fail-on` defaults to `low`, so info-level findings are reported without
failing CI; use `--fail-on info` to fail on those too. `--min-severity` controls
which findings are reported at all, and repeated `--disable RULE_ID` options
record reviewed exceptions. The default maximum access-token lifetime is 900
seconds; change it with `--max-access-token-lifetime`.

Shared policy can be stored in TOML and used by both `lint` and `diff`:

```toml
[oidc-audit]
format = "sarif"
min-severity = "medium"
fail-on = "medium"
disable = ["OIDC-META-008"]
max-access-token-lifetime = 900
include-keycloak-builtins = false
timeout = 10.0
```

```console
oidc-audit lint --config oidc-audit.toml --issuer https://login.example.test/realms/main
```

Explicit CLI options override their config-file equivalents. Repeated
`--disable` options are combined with configured exceptions.

Keycloak-managed clients (`account`, `account-console`, `admin-cli`, `broker`,
`realm-management`, and `security-admin-console`) are skipped by default.
Use `--include-keycloak-builtins` only when deliberately auditing Keycloak's
own internal client registrations. Every wildcard redirect URI on any other
client is reported, including `*` on its own and relative paths such as `/*`,
which Keycloak resolves against the client's root URL.

## Local Keycloak lab

The examples contain a deliberately vulnerable realm and a clean realm:

```console
docker compose -f examples/docker-compose.yml up -d
```

Keycloak then listens only on `127.0.0.1:8080` and imports two realms,
`good-realm` and `bad-realm`. Keycloak requires each import file to be named
`<realm>-realm.json`, which the compose file handles. The bundled credentials
are for this disposable local lab only.

Audit both realms through their live metadata:

```console
oidc-audit lint --issuer http://127.0.0.1:8080/realms/good-realm
oidc-audit lint --issuer http://127.0.0.1:8080/realms/bad-realm
```

Live metadata cannot show per-client settings, so both realms report the same
info-level Keycloak findings. The difference between them shows up in their
exports: `oidc-audit lint --keycloak examples/bad-realm.json`.

## Scope

Version 0.2 supports offline JSON files, read-only issuer discovery, and
Keycloak export regression diffing. It does not attempt authentication,
dynamic client registration, token issuance, or active security probing. See
[PLAN.md](PLAN.md) for the roadmap.


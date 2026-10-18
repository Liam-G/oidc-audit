"""The public rule catalogue, including normative references and remediation."""

from __future__ import annotations

from .models import Rule, Severity


def _r(
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    remediation: str,
    reference: str,
    reference_url: str | None = None,
) -> Rule:
    if reference_url is None:
        rfc, section = reference.split(" §", 1)
        reference_url = f"https://www.rfc-editor.org/rfc/{rfc.lower()}.html#section-{section}"
    return Rule(rule_id, severity, title, message, remediation, reference, reference_url)


OIDC_DISCOVERY_METADATA = (
    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
)


RULES = {
    rule.id: rule
    for rule in (
        _r(
            "OIDC-META-001",
            Severity.HIGH,
            "Issuer mismatch",
            "The metadata issuer does not match the expected issuer.",
            "Publish metadata under the exact issuer URL and configure clients "
            "to require that value.",
            "RFC8414 §3.3",
        ),
        _r(
            "OIDC-META-002",
            Severity.HIGH,
            "Insecure endpoint",
            "An advertised endpoint does not use HTTPS.",
            "Serve authorization-server endpoints over HTTPS; only loopback "
            "development endpoints are exempted by this audit.",
            "RFC8414 §3.1",
        ),
        _r(
            "OIDC-META-003",
            Severity.MEDIUM,
            "Implicit flow advertised",
            "A response type that issues an access token from the authorization "
            "endpoint is advertised.",
            "Disable implicit and hybrid response types that include token; use "
            "authorization code with PKCE.",
            "RFC9700 §2.1.2",
        ),
        _r(
            "OIDC-META-004",
            Severity.HIGH,
            "Password grant advertised",
            "The resource owner password credentials grant is advertised.",
            "Disable the password grant and use a redirect-based authorization code flow.",
            "RFC9700 §2.4",
        ),
        _r(
            "OIDC-META-005",
            Severity.HIGH,
            "Strong PKCE support not advertised",
            "The metadata does not advertise S256 PKCE support.",
            "Enable PKCE with S256 and advertise it in code_challenge_methods_supported.",
            "RFC9700 §2.1.1",
        ),
        _r(
            "OIDC-META-006",
            Severity.MEDIUM,
            "Unsigned ID tokens advertised",
            "The none ID-token signing algorithm is advertised. OpenID Connect allows "
            "this only for response types that return no ID token from the "
            "authorization endpoint.",
            "Remove none unless it is required, and confirm that no client can "
            "receive an unsigned ID token from the authorization endpoint.",
            "OIDC Discovery §3",
            OIDC_DISCOVERY_METADATA,
        ),
        _r(
            "OIDC-META-007",
            Severity.HIGH,
            "Only symmetric ID-token signing advertised",
            "All advertised ID-token signing algorithms use shared secrets, so RS256 "
            "is missing although OpenID Connect requires it.",
            "Advertise RS256, and prefer an asymmetric algorithm for ID tokens.",
            "OIDC Discovery §3",
            OIDC_DISCOVERY_METADATA,
        ),
        _r(
            "OIDC-META-008",
            Severity.INFO,
            "PAR not advertised",
            "No pushed authorization request endpoint is advertised.",
            "Consider enabling PAR and advertising pushed_authorization_request_endpoint.",
            "RFC9126 §2",
        ),
        _r(
            "OIDC-META-009",
            Severity.HIGH,
            "JWKS URI missing or insecure",
            "jwks_uri is missing or does not use HTTPS.",
            "Publish the public JWK Set at an HTTPS URL in jwks_uri.",
            "RFC8414 §2",
        ),
        _r(
            "OIDC-META-010",
            Severity.INFO,
            "Implicit response types advertised by Keycloak",
            "Keycloak advertises token-issuing response types for every realm; whether "
            "a client can use them is a per-client setting.",
            "Audit the realm export with --keycloak; OIDC-CLIENT-005 reports any "
            "client that has the implicit flow enabled.",
            "RFC9700 §2.1.2",
        ),
        _r(
            "OIDC-META-011",
            Severity.INFO,
            "Password grant advertised by Keycloak",
            "Keycloak advertises the password grant for every realm; whether a client "
            "can use it is a per-client setting.",
            "Audit the realm export with --keycloak; OIDC-CLIENT-006 reports any "
            "client that has direct access grants enabled.",
            "RFC9700 §2.4",
        ),
        _r(
            "OIDC-KEY-001",
            Severity.CRITICAL,
            "Private key material published",
            "A published JWK contains private-key parameters.",
            "Rotate the affected key immediately and publish only its public parameters.",
            "RFC7517 §9.2",
        ),
        _r(
            "OIDC-KEY-002",
            Severity.CRITICAL,
            "Shared-secret key published",
            "A symmetric oct key appears in the published JWK Set.",
            "Remove and rotate the shared secret; publish asymmetric public keys only.",
            "RFC7518 §6.4",
        ),
        _r(
            "OIDC-KEY-003",
            Severity.HIGH,
            "Weak RSA key",
            "An RSA key has a modulus shorter than 2048 bits.",
            "Generate and rotate to an RSA key of at least 2048 bits.",
            "RFC7518 §3.3",
        ),
        _r(
            "OIDC-KEY-004",
            Severity.HIGH,
            "Non-standard EC curve",
            "An EC key uses a curve outside the JWA registered curves.",
            "Use P-256, P-384, or P-521 for an EC JWK.",
            "RFC7518 §6.2.1.1",
        ),
        _r(
            "OIDC-KEY-005",
            Severity.MEDIUM,
            "Key ID missing",
            "A published JWK has no non-empty kid.",
            "Assign every published key a stable, unique kid to support safe rotation.",
            "RFC7517 §4.5",
        ),
        _r(
            "OIDC-KEY-006",
            Severity.HIGH,
            "Duplicate key ID",
            "More than one published JWK uses the same kid.",
            "Give each key in the JWK Set a distinct kid.",
            "RFC7517 §4.5",
        ),
        _r(
            "OIDC-KEY-007",
            Severity.LOW,
            "Key use missing",
            "A published JWK has no use or key_ops declaration.",
            "Declare the intended signing or encryption use for the key.",
            "RFC7517 §4.2",
        ),
        _r(
            "OIDC-KEY-008",
            Severity.LOW,
            "Key algorithm missing",
            "A published JWK has no alg declaration.",
            "Declare the algorithm intended for the key.",
            "RFC7517 §4.4",
        ),
        _r(
            "OIDC-CLIENT-001",
            Severity.CRITICAL,
            "Wildcard redirect URI",
            "A client redirect URI contains a wildcard.",
            "Register every redirect URI explicitly and require exact matching.",
            "RFC9700 §2.1",
        ),
        _r(
            "OIDC-CLIENT-002",
            Severity.HIGH,
            "Insecure redirect URI",
            "A non-loopback client redirect URI uses HTTP.",
            "Use HTTPS redirect URIs outside native-app loopback callbacks.",
            "RFC8252 §7.3",
        ),
        _r(
            "OIDC-CLIENT-003",
            Severity.MEDIUM,
            "Localhost redirect in production",
            "A production realm client redirects to localhost or a loopback address.",
            "Remove development redirect URIs from production clients.",
            "RFC9700 §2.1",
        ),
        _r(
            "OIDC-CLIENT-004",
            Severity.HIGH,
            "Public client does not enforce S256 PKCE",
            "A public client does not require the S256 PKCE method.",
            "Set pkce.code.challenge.method to S256 for the public client.",
            "RFC9700 §2.1.1",
        ),
        _r(
            "OIDC-CLIENT-005",
            Severity.HIGH,
            "Implicit flow enabled",
            "A client has the implicit flow enabled.",
            "Disable implicit flow and use authorization code with PKCE.",
            "RFC9700 §2.1.2",
        ),
        _r(
            "OIDC-CLIENT-006",
            Severity.HIGH,
            "Direct access grants enabled",
            "A client has the password grant enabled.",
            "Disable direct access grants and use a redirect-based flow.",
            "RFC9700 §2.4",
        ),
        _r(
            "OIDC-CLIENT-007",
            Severity.MEDIUM,
            "Long access-token lifetime",
            "A client's effective access-token lifetime exceeds the configured maximum.",
            "Reduce the realm or client access-token lifetime to limit replay impact.",
            "RFC9700 §2.2.1",
        ),
        _r(
            "OIDC-CLIENT-008",
            Severity.HIGH,
            "Refresh-token rotation disabled",
            "A public client can receive refresh tokens but realm rotation is disabled.",
            "Enable Revoke Refresh Token in the realm and use refresh-token rotation.",
            "RFC9700 §2.2.2",
        ),
        _r(
            "OIDC-CLIENT-009",
            Severity.MEDIUM,
            "Client secret present in export",
            "The realm export contains client secret material.",
            "Treat the export as sensitive, redact it before sharing, and prefer "
            "secret-free partial exports.",
            "RFC6749 §2.3.1",
        ),
    )
}

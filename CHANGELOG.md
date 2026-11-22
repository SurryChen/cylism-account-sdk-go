# Changelog

## Unreleased

- Correct the application email-code response contract: SendPasswordEmailCode returns PasswordEmailCodeAccepted with Message, ExpiresIn and RetryAfter. BrowserEmailCode and BindEmailCode retain EmailCodeAccepted with Ok.
- Reject malformed or expired access tokens in CompleteLogin, Refresh and TokenSession; do not persist invalid refresh results or replay their old refresh tokens.
- Add Config.MaxResponseBytes, default 2 MiB, covering all SDK HTTP responses including dependency-owned OIDC requests.
- Honor same-origin introspection_endpoint and revocation_endpoint metadata after successful DiscoverOIDC. Config.IntrospectionEndpoint / RevocationEndpoint override metadata; Account paths remain the fallback.

### Migration from v0.1.0

Code that explicitly declares the return value of SendPasswordEmailCode as EmailCodeAccepted must change it to PasswordEmailCodeAccepted (or use inferred assignment). Check err for request success; this application response has no Ok field. Do not display remote Message without the application's own error/message policy.

Expired, unknown-expiry or non-Bearer token results previously accepted now return an error and require reauthentication. Callers should keep refresh serialization, atomic persistence, online revocation checks and business authorization.

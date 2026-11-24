# Changelog

## Unreleased

- Add administrator methods to inspect, enable/revoke, and audit the independent password API grant on an existing application. Enabling preserves application credentials and OIDC settings; revoking invalidates only opaque password bridge sessions.

- Make local authentication and permission caches the default for Can, RequirePermission, ApplicationEntitlements, Introspect, AuthenticateBearer and VerifyPasswordSession. Refresh individual active entries in the background (30 seconds), enforce a maximum 60-second lease and expire idle entries after five minutes. Coalesce lookups, bound capacity/concurrency and add Client.Close.
- Add explicit Online check methods and CacheConfig.Disabled for immediate checks. Successful SDK mutations/revocation invalidate local caches; remote changes propagate within cache validity. Account must be upgraded first to supply permission version/valid_until. Token/session expiration remains a hard bound.

- Correct the application email-code response contract: SendPasswordEmailCode returns PasswordEmailCodeAccepted with Message, ExpiresIn and RetryAfter. BrowserEmailCode and BindEmailCode retain EmailCodeAccepted with Ok.
- Reject malformed or expired access tokens in CompleteLogin, Refresh and TokenSession; do not persist invalid refresh results or replay their old refresh tokens.
- Add Config.MaxResponseBytes, default 2 MiB, covering all SDK HTTP responses including dependency-owned OIDC requests.
- Honor same-origin introspection_endpoint and revocation_endpoint metadata after successful DiscoverOIDC. Config.IntrospectionEndpoint / RevocationEndpoint override metadata; Account paths remain the fallback.

### Migration from v0.1.0

Code that explicitly declares the return value of SendPasswordEmailCode as EmailCodeAccepted must change it to PasswordEmailCodeAccepted (or use inferred assignment). Check err for request success; this application response has no Ok field. Do not display remote Message without the application's own error/message policy.

Expired, unknown-expiry or non-Bearer token results previously accepted now return an error and require reauthentication. Callers should keep refresh serialization, atomic persistence and business authorization. Authentication/revocation checks now use bounded caching by default; choose explicit Online checks for operations requiring immediate verification.

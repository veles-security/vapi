# Authentication chains

Package `aut` combines implementations of `vapi.Authenticator[R]` into a
single authentication policy. Policies can express alternative mechanisms
with `OR`, required factors with `AND`, or a mixture of both.

## OR: alternative authentication mechanisms

Use `OR` when any one mechanism is sufficient:

```go
policy := aut.OR(
	bearerTokenAuthenticator,
	apiKeyAuthenticator,
)

principal, err := policy.Authenticate(ctx, request)
```

Authenticators are evaluated from left to right. The first successful result
is returned and later alternatives are not called.

`Chain` is the underlying OR chain type. A `Chain` literal has the same
behavior and is useful when the authenticators are already stored as values:

```go
policy := aut.Chain[*http.Request]{
	bearerTokenAuthenticator,
	apiKeyAuthenticator,
}
```

`OR(...)` is generally more concise and supports generic type inference.

## AND: required authentication factors

Use `AND` when every mechanism must authenticate the request:

```go
policy := aut.AND(
	apiKeyAuthenticator,
	mtlsAuthenticator,
)
```

Authenticators are evaluated from left to right and evaluation stops at the
first error. When all factors succeed, the principal from the first
authenticator is returned. Later authenticators validate additional required
factors; their principals are not merged into the result. Put the primary
identity authenticator first and additional proof authenticators after it.

## Combining AND and OR

Nest policies to make the intended grouping explicit. For example, to accept
either a bearer token or the combination of an API key and mutual TLS:

```go
policy := aut.OR(
	bearerTokenAuthenticator,
	aut.AND(
		apiKeyAuthenticator,
		mtlsAuthenticator,
	),
)
```

This policy means:

```text
BearerTokenAuthenticator OR (APIKeyAuthenticator AND MTLSAuthenticator)
```

`AND` and `OR` both produce `vapi.Authenticator[R]` values, so they can be
nested to build more involved policies:

```go
policy := aut.AND(
	aut.OR(bearerTokenAuthenticator, apiKeyAuthenticator),
	mtlsAuthenticator,
)
```

This second policy means:

```text
(BearerTokenAuthenticator OR APIKeyAuthenticator) AND MTLSAuthenticator
```

## Error behavior

Authentication errors determine whether a policy may try another branch:

| Result | `OR` behavior | `AND` behavior |
| --- | --- | --- |
| Success | Return the principal immediately | Continue with the next required factor |
| `vapi.ErrNotApplicable` | Try the next alternative | Fail the current AND group |
| Any other error | Stop and return the error | Stop and return the error |

An authenticator should return `vapi.ErrNotApplicable` only when its
credential type is absent or does not apply to the request. If it recognizes
credentials but they are malformed, expired, or invalid, it should return the
corresponding authentication error. This prevents invalid credentials from
falling through to a weaker or unrelated mechanism.

If no OR alternative applies, the chain returns `vapi.ErrUnauthenticated`.
Empty `OR` and `AND` policies also return `vapi.ErrUnauthenticated`.

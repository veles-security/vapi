package vapi

import (
	"context"
	"time"
)

// Artifacter is the minimal immutable representation of a parsed or newly constructed protocol object.
type Artifacter interface {
	Kind() string
}

// PrincipalArtifacter marks artifacts that identify a principal.
type PrincipalArtifacter interface {
	Artifacter
	Principal() Principaler
}

// RequestArtifacter marks artifacts that represent a request.
type RequestArtifacter interface {
	Artifacter
	RequestID() string
}

// ResponseArtifacter marks artifacts that represent a response.
type ResponseArtifacter interface {
	Artifacter
	StatusCode() int
}

// Principaler describes an authenticated principal and its associated claims and provenance.
// Implementations may vary by protocol or deployment context, so this is an interface rather than a concrete struct.
type Principaler interface {
	// Issuer returns the security domain or authority that issued the identity evidence.
	// Examples: OIDC id_token issuer "https://issuer.example"; SAML Issuer element or IdP entityID.
	Issuer() string

	// Subject returns the stable subject identifier for the principal within the issuer's namespace.
	// Examples: OIDC sub claim; SAML NameID value or Subject/NameID.
	Subject() string

	// Kind identifies the principal category, such as user, service, device, or anonymous.
	// Examples: OIDC typically uses a user or service-like interpretation; SAML may represent users or service principals.
	Kind() string

	// DisplayName returns a human-facing name for the principal where available.
	// Examples: OIDC name or preferred_username; SAML cn or displayName attribute.
	DisplayName() string

	// Username returns a login or account identifier that is commonly used by applications.
	// Examples: OIDC preferred_username or email; SAML uid or samAccountName attribute.
	Username() string

	// Email returns the principal's email address when present.
	// Examples: OIDC email; SAML mail attribute.
	Email() string

	// IssuedAt returns the time at which the identity evidence was issued.
	// Examples: OIDC iat; SAML Conditions NotBefore or assertion issue instant.
	IssuedAt() time.Time

	// AuthenticatedAt returns the time at which the principal was authenticated.
	// Examples: OIDC auth_time; SAML AuthnInstant.
	AuthenticatedAt() time.Time

	// AuthenticationMethod returns the authentication method or mechanism used.
	// Examples: OIDC amr values such as "pwd" or "mfa"; SAML AuthnContextClassRef.
	AuthenticationMethod() string

	// AuthenticationContext returns additional context about the authentication event.
	// Examples: OIDC acr, auth context URI, or tenant context; SAML AuthnContext or authentication statement details.
	AuthenticationContext() string

	// AssuranceLevel returns a numeric or ordinal assurance signal for the authentication strength.
	// Examples: OIDC acr interpretation mapped to 0/1/2+; SAML assurance URI translated into a comparable level.
	AssuranceLevel() int

	// Claims returns protocol-neutral claims that describe the principal.
	// Examples: OIDC standard claims such as name, email, groups; SAML attributes such as role or department.
	Claims() map[string]any

	// Attributes returns additional attributes that may not be represented as standard claims.
	// Examples: OIDC custom claims under a namespace; SAML custom attributes or extensions.
	Attributes() map[string]any

	// Actor returns a delegated or acting principal when the identity context includes delegation.
	// Examples: OIDC act claim; SAML acting subject or delegated identity.
	Actor() Principaler

	// Source describes the provenance of the principal, such as the protocol or upstream system.
	// Examples: "oidc:id_token", "saml:assertion", or "ldap:active-directory".
	Source() string
}

// DecodeSchemer decodes an explicitly selected representation into A.
// Implementations must enforce limits before expensive processing.
type DecodeSchemer[A Artifacter, O any] interface {
	Decode(ctx context.Context, encoded []byte, options ...O) (A, error)
}

// EncodeSchemer encodes A into an explicitly selected representation.
type EncodeSchemer[A Artifacter, O any] interface {
	Encode(ctx context.Context, artifact A, options ...O) ([]byte, error)
}

// ValidationSchemer validates an artifact of type A using scheme-specific
// options O.
type ValidationSchemer[A Artifacter, O any] interface {
	Validate(ctx context.Context, artifact A, options ...O) error
}

// IssueSchemer issues an artifact of type A using scheme-specific options O.
type IssueSchemer[O any, A Artifacter] interface {
	Issue(ctx context.Context, options ...O) (A, error)
}

// ExchangeSchemer exchanges an artifact of type SA into an artifact of type TA
// using scheme-specific options O.
type ExchangeSchemer[SA Artifacter, TA Artifacter, O any] interface {
	Exchange(ctx context.Context, artifact SA, options ...O) (TA, error)
}

// Authenticator derives a principal from a request.
type AuthSchemer[R any] interface {
	Authenticate(ctx context.Context, request R) (Principaler, error)
}

type AuthApplierSchemer[R any] interface {
	ApplyAuthentication(ctx context.Context, request R, principal Principal) error
}

// ArtifactInjector writes an artifact into a carrier such as an HTTP request
// or response.
type InjectorSchemer[C any, A Artifacter, O any] interface {
	InjectArtifact(ctx context.Context, carrier C, artifact A, options ...O) error
}

// ArtifactExtractor reads an artifact from a carrier such as an HTTP request
// or response.
type ExtractorSchemer[C any, A Artifacter, O any] interface {
	ExtractArtifact(ctx context.Context, carrier C, options ...O) (A, error)
}

type PrincipalSchemer[A Artifacter, O any] interface {
	ExtractPrincipal(ctx context.Context, artifact A, options ...O) (Principaler, error)
}

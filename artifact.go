package vapi

import (
	"context"
	"time"
)

// Artifact is the minimal immutable representation of a parsed or newly constructed protocol object.
type Artifact interface {
	Kind() string
}

// PrincipalArtifact marks artifacts that identify a principal.
type PrincipalArtifact interface {
	Artifact
	Principal() Principal
}

// RequestArtifact marks artifacts that represent a request.
type RequestArtifact interface {
	Artifact
	RequestID() string
}

// ResponseArtifact marks artifacts that represent a response.
type ResponseArtifact interface {
	Artifact
	StatusCode() int
}

// Principal describes an authenticated principal and its associated claims and provenance.
// Implementations may vary by protocol or deployment context, so this is an interface rather than a concrete struct.
type Principal interface {
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
	Actor() Principal

	// Source describes the provenance of the principal, such as the protocol or upstream system.
	// Examples: "oidc:id_token", "saml:assertion", or "ldap:active-directory".
	Source() string
}

// ScopedPrincipal describes a principal whose authenticating credential grants
// a set of authorization scopes.
//
// GrantedScopes returns the scopes granted by the credential that produced the
// principal. It does not describe all scopes that the principal may be allowed
// to request.
type ScopedPrincipal interface {
	Principal
	GrantedScopes() []string
}

// Decoder decodes an explicitly selected representation into A.
// Implementations must enforce limits before expensive processing.
type Decoder[A Artifact, O any] interface {
	Decode(ctx context.Context, encoded []byte, options ...O) (A, error)
}

// Encoder encodes A into an explicitly selected representation.
type Encoder[A Artifact, O any] interface {
	Encode(ctx context.Context, artifact A, options ...O) ([]byte, error)
}

// Validator validates an artifact of type A using scheme-specific
// options O.
type Validator[A Artifact, O any] interface {
	Validate(ctx context.Context, artifact A, options ...O) error
}

// Issuer issues an artifact of type A using scheme-specific options O.
type Issuer[O any, A Artifact] interface {
	Issue(ctx context.Context, options ...O) (A, error)
}

// PrincipalIssuer issues an artifact of type A for given principal.
type PrincipalIssuer[O any, A Artifact] interface {
	IssueForPrincipal(ctx context.Context, principal Principal) (A, error)
}

// Exchanger exchanges an artifact of type SA into an artifact of type TA
// using scheme-specific options O.
type Exchanger[SA Artifact, TA Artifact, O any] interface {
	Exchange(ctx context.Context, artifact SA, options ...O) (TA, error)
}

// Authenticator derives a principal from a request.
type Authenticator[R any] interface {
	Authenticate(ctx context.Context, request R) (Principal, error)
}

type AuthApplier[R any] interface {
	ApplyAuthentication(ctx context.Context, request R, principal Principal) error
}

// Writer writes an artifact into a carrier such as an HTTP request
// or response.
type Writer[C any, A Artifact, O any] interface {
	WriteArtifact(ctx context.Context, carrierWriter C, artifact A, options ...O) error
}

// Reader reads an artifact from a carrier such as an HTTP request
// or response.
type Reader[C any, A Artifact, O any] interface {
	ReadArtifact(ctx context.Context, carrier C, options ...O) (A, error)
}

// Extracts Principaler from an artifact A
// For example Principaler from JWT token
type PrincipalExtractor[A Artifact, O any] interface {
	ExtractPrincipal(ctx context.Context, artifact A, options ...O) (Principal, error)
}

type Signer[A Artifact, O any] interface {
	Sign(ctx context.Context, artifact A, options ...O) ([]byte, error)
}

type SignatureVerifier[O any] interface {
	VerifySignature(signature []byte, digest []byte, options ...O) error
}

package sub

import (
	"slices"
	"time"

	"github.com/veles-security/vapi"
)

// Principal is a default, protocol-neutral implementation of Principal.
type Principal struct {
	issuer                string
	subject               string
	kind                  string
	displayName           string
	username              string
	email                 string
	issuedAt              time.Time
	authenticatedAt       time.Time
	authenticationMethod  string
	authenticationContext string
	assuranceLevel        int
	claims                map[string]any
	attributes            map[string]any
	actor                 vapi.Principal
	source                string
	grantedScopes         []string
}

func (p *Principal) Issuer() string {
	if p == nil {
		return ""
	}
	return p.issuer
}
func (p *Principal) Subject() string {
	if p == nil {
		return ""
	}
	return p.subject
}
func (p *Principal) Kind() string {
	if p == nil {
		return ""
	}
	return p.kind
}
func (p *Principal) DisplayName() string {
	if p == nil {
		return ""
	}
	return p.displayName
}
func (p *Principal) Username() string {
	if p == nil {
		return ""
	}
	return p.username
}
func (p *Principal) Email() string {
	if p == nil {
		return ""
	}
	return p.email
}
func (p *Principal) IssuedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.issuedAt
}
func (p *Principal) AuthenticatedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.authenticatedAt
}
func (p *Principal) AuthenticationMethod() string {
	if p == nil {
		return ""
	}
	return p.authenticationMethod
}
func (p *Principal) AuthenticationContext() string {
	if p == nil {
		return ""
	}
	return p.authenticationContext
}
func (p *Principal) AssuranceLevel() int {
	if p == nil {
		return 0
	}
	return p.assuranceLevel
}
func (p *Principal) Claims() map[string]any {
	if p == nil {
		return nil
	}
	return cloneStringAnyMap(p.claims)
}
func (p *Principal) Attributes() map[string]any {
	if p == nil {
		return nil
	}
	return cloneStringAnyMap(p.attributes)
}
func (p *Principal) Actor() vapi.Principal {
	if p == nil {
		return nil
	}
	return p.actor
}
func (p *Principal) Source() string {
	if p == nil {
		return ""
	}
	return p.source
}

// GrantedScopes returns a defensive copy of the authorization scopes granted
// by the credential that produced the principal.
func (p *Principal) GrantedScopes() []string {
	if p == nil {
		return nil
	}
	return slices.Clone(p.grantedScopes)
}

// NewBasePrincipal creates a default principal implementation with the minimum identifying fields.
func NewBasePrincipal(issuer, subject, kind string) *Principal {
	return &Principal{issuer: issuer, subject: subject, kind: kind}
}

// WithDisplayName sets the display name.
func (p *Principal) WithDisplayName(name string) *Principal {
	if p == nil {
		return nil
	}
	p.displayName = name
	return p
}

// WithUsername sets the username.
func (p *Principal) WithUsername(username string) *Principal {
	if p == nil {
		return nil
	}
	p.username = username
	return p
}

// WithEmail sets the email.
func (p *Principal) WithEmail(email string) *Principal {
	if p == nil {
		return nil
	}
	p.email = email
	return p
}

// WithIssuedAt sets the time at which the identity evidence was issued.
func (p *Principal) WithIssuedAt(issuedAt time.Time) *Principal {
	if p == nil {
		return nil
	}
	p.issuedAt = issuedAt
	return p
}

// WithAuthenticatedAt sets the time at which the principal authenticated.
func (p *Principal) WithAuthenticatedAt(authenticatedAt time.Time) *Principal {
	if p == nil {
		return nil
	}
	p.authenticatedAt = authenticatedAt
	return p
}

// WithAuthentication sets the authentication method, context, and assurance.
func (p *Principal) WithAuthentication(method, context string, assurance int) *Principal {
	if p == nil {
		return nil
	}
	p.authenticationMethod = method
	p.authenticationContext = context
	p.assuranceLevel = assurance
	return p
}

// WithSource sets the artifact provenance description.
func (p *Principal) WithSource(source string) *Principal {
	if p == nil {
		return nil
	}
	p.source = source
	return p
}

// WithClaims replaces the principal claims with a defensive copy.
func (p *Principal) WithClaims(claims map[string]any) *Principal {
	if p == nil {
		return nil
	}
	p.claims = cloneStringAnyMap(claims)
	return p
}

// WithAttributes replaces the principal attributes with a defensive copy.
func (p *Principal) WithAttributes(attributes map[string]any) *Principal {
	if p == nil {
		return nil
	}
	p.attributes = cloneStringAnyMap(attributes)
	return p
}

// WithActor sets the actor principal.
func (p *Principal) WithActor(actor vapi.Principal) *Principal {
	if p == nil {
		return nil
	}
	p.actor = actor
	return p
}

// WithGrantedScopes replaces the authorization scopes granted by the
// credential that produced the principal.
func (p *Principal) WithGrantedScopes(scopes ...string) *Principal {
	if p == nil {
		return nil
	}
	p.grantedScopes = slices.Clone(scopes)
	return p
}

var _ vapi.ScopedPrincipal = (*Principal)(nil)

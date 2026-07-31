package art

import "github.com/veles-security/vapi"

// ArtifactBase is a simple concrete implementation of the common artifact capabilities.
type ArtifactBase struct {
	kind       string
	requestID  string
	statusCode int
}

// NewArtifactBase creates a new base artifact with the provided kind.
func NewArtifactBase(kind string) *ArtifactBase {
	return &ArtifactBase{kind: kind}
}

// Kind returns the artifact kind.
func (a *ArtifactBase) Kind() string {
	if a == nil {
		return ""
	}
	return a.kind
}

// RequestID returns the optional request identifier.
func (a *ArtifactBase) RequestID() string {
	if a == nil {
		return ""
	}
	return a.requestID
}

// StatusCode returns the optional response status code.
func (a *ArtifactBase) StatusCode() int {
	if a == nil {
		return 0
	}
	return a.statusCode
}

// WithRequestID sets the request identifier for the artifact.
func (a *ArtifactBase) WithRequestID(id string) *ArtifactBase {
	if a == nil {
		return nil
	}
	a.requestID = id
	return a
}

// WithStatusCode sets the response status code for the artifact.
func (a *ArtifactBase) WithStatusCode(code int) *ArtifactBase {
	if a == nil {
		return nil
	}
	a.statusCode = code
	return a
}

var _ vapi.Artifact = &ArtifactBase{}

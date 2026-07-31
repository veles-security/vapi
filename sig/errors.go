package sig

import (
	"errors"
)

// Configuration error kinds. Configuration failures are also categorized as
// vapi.ErrMisconfigured.
var (
	ErrInvalidAlgorithm     = errors.New("invalid signature algorithm")
	ErrInvalidKey           = errors.New("invalid signature key")
	ErrAlgorithmKeyMismatch = errors.New("signature algorithm and key mismatch")

	// Input error kinds. Malformed inputs are also categorized as
	// vapi.ErrMalformed; a well-formed signature which does not verify is
	// reported as vapi.ErrInvalidSignature instead.
	ErrMalformedSignature = errors.New("malformed signature")
	ErrMalformedDigest    = errors.New("malformed digest")
)

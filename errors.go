package vapi

import "errors"

var (
	ErrMalformed        = errors.New("malformed")
	ErrMisconfigured    = errors.New("misconfigured")
	ErrUnsupported      = errors.New("unsupported")
	ErrUntrusted        = errors.New("untrusted")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrDecryption       = errors.New("decryption failure")
	ErrNotYetValid      = errors.New("not yet valid")
	ErrExpired          = errors.New("expired")
	ErrWrongIssuer      = errors.New("wrong issuer")
	ErrWrongAudience    = errors.New("wrong audience")
	ErrReplay           = errors.New("replayed")
	ErrBinding          = errors.New("binding failure")
	ErrPolicyRejected   = errors.New("policy rejected")
	ErrLimitExceeded    = errors.New("resource limit exceeded")
	ErrUnavailable      = errors.New("temporarily unavailable")
	ErrInternal         = errors.New("internal failure")
	ErrNotApplicable    = errors.New("not applicable")
	ErrUnauthenticated  = errors.New("unauthenticated")
)

// ErrorCategory is a stable machine-testable category for API failures.
type ErrorCategory struct {
	Category error
	Cause    error
}

func (e *ErrorCategory) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause == nil {
		return e.Category.Error()
	}
	return e.Category.Error() + ": " + e.Cause.Error()
}

func (e *ErrorCategory) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is makes the stable category discoverable with errors.Is while preserving
// the underlying cause through Unwrap.
func (e *ErrorCategory) Is(target error) bool {
	return e != nil && (target == e.Category || errors.Is(e.Cause, target))
}

func NewErrorCategory(category error, cause error) error {
	if category == nil {
		category = ErrInternal
	}
	return &ErrorCategory{Category: category, Cause: cause}
}

func IsCategory(err error, category error) bool {
	if err == nil {
		return false
	}
	var ec *ErrorCategory
	if errors.As(err, &ec) {
		return ec.Category == category
	}
	return err == category
}

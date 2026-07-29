package vapi

import (
	"errors"
	"testing"
)

func TestErrorCategorySupportsErrorsIs(t *testing.T) {
	cause := errors.New("cause")
	err := NewErrorCategory(ErrUnauthenticated, NewErrorCategory(ErrExpired, cause))

	tests := []struct {
		name   string
		target error
		want   bool
	}{
		{name: "outer category", target: ErrUnauthenticated, want: true},
		{name: "nested category", target: ErrExpired, want: true},
		{name: "cause", target: cause, want: true},
		{name: "unrelated", target: ErrMalformed, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := errors.Is(err, test.target); got != test.want {
				t.Fatalf("errors.Is() = %v, want %v", got, test.want)
			}
		})
	}
}

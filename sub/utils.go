package sub

import "github.com/veles-security/vapi"

// CloneClaims returns a defensive copy of the principal claims.
func CloneClaims(p vapi.Principal) map[string]any {
	if p == nil {
		return nil
	}
	return cloneStringAnyMap(p.Claims())
}

// CloneAttributes returns a defensive copy of the principal attributes.
func CloneAttributes(p vapi.Principal) map[string]any {
	if p == nil {
		return nil
	}
	return cloneStringAnyMap(p.Attributes())
}

func cloneStringAnyMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}

	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = cloneAny(value)
	}
	return cloned
}

func cloneAny(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneStringAnyMap(value)
	case []any:
		cloned := make([]any, len(value))
		for index, item := range value {
			cloned[index] = cloneAny(item)
		}
		return cloned
	case []string:
		return append([]string(nil), value...)
	default:
		return value
	}
}

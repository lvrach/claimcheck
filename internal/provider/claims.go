package provider

import (
	"fmt"
)

// ValidateClaims checks that extra claims don't exceed configured limits.
func ValidateClaims(claims map[string]any, maxFields, maxDepth, maxValueBytes int) error {
	if len(claims) > maxFields {
		return fmt.Errorf("too many claim fields")
	}
	for k, v := range claims {
		if len(k) > 128 {
			return fmt.Errorf("claim key too long: %s", k)
		}
		if err := validateClaimValue(v, 1, maxDepth, maxValueBytes); err != nil {
			return fmt.Errorf("claim %q: %w", k, err)
		}
	}
	return nil
}

func validateClaimValue(v any, depth, maxDepth, maxValueBytes int) error {
	if depth > maxDepth {
		return fmt.Errorf("claim nesting too deep")
	}
	switch x := v.(type) {
	case string:
		if len(x) > maxValueBytes {
			return fmt.Errorf("string value too large")
		}
	case float64, bool, int, int64, nil:
		return nil
	case []any:
		if len(x) > 64 {
			return fmt.Errorf("array too large")
		}
		for _, item := range x {
			if err := validateClaimValue(item, depth+1, maxDepth, maxValueBytes); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(x) > 64 {
			return fmt.Errorf("object too large")
		}
		for k, item := range x {
			if len(k) > 128 {
				return fmt.Errorf("nested key too long")
			}
			if err := validateClaimValue(item, depth+1, maxDepth, maxValueBytes); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported claim value type")
	}
	return nil
}

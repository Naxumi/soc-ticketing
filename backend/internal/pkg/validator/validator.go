package validator

import "strings"

type ValidationError struct {
	Field   string
	Message string
}

type ValidationErrors []ValidationError

func (v ValidationErrors) Error() string {
	if len(v) == 0 {
		return "validation error"
	}
	// Keep it short; HTTP layer can render field-wise details.
	return v[0].Field + ": " + v[0].Message
}

func (v ValidationErrors) ToMap() map[string]string {
	m := make(map[string]string, len(v))
	for _, e := range v {
		if e.Field == "" {
			continue
		}
		m[e.Field] = e.Message
	}
	return m
}

func IsEmpty(s string) bool { return strings.TrimSpace(s) == "" }

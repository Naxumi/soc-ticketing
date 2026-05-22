package validator

import "testing"

func TestIsEmpty(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", true},
		{"  ", true},
		{"\t\n", true},
		{"hello", false},
		{" hello ", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsEmpty(tt.input); got != tt.expected {
				t.Errorf("IsEmpty(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestValidationErrors_Error(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		var errs ValidationErrors
		if got := errs.Error(); got != "validation error" {
			t.Errorf("expected 'validation error', got %q", got)
		}
	})

	t.Run("single error", func(t *testing.T) {
		errs := ValidationErrors{{Field: "name", Message: "is required"}}
		if got := errs.Error(); got != "name: is required" {
			t.Errorf("expected 'name: is required', got %q", got)
		}
	})

	t.Run("multiple errors returns first", func(t *testing.T) {
		errs := ValidationErrors{
			{Field: "email", Message: "is required"},
			{Field: "password", Message: "too short"},
		}
		if got := errs.Error(); got != "email: is required" {
			t.Errorf("expected first error, got %q", got)
		}
	})
}

func TestValidationErrors_ToMap(t *testing.T) {
	errs := ValidationErrors{
		{Field: "email", Message: "is required"},
		{Field: "password", Message: "too short"},
		{Field: "", Message: "should be skipped"},
	}

	m := errs.ToMap()
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m["email"] != "is required" {
		t.Errorf("expected 'is required' for email, got %q", m["email"])
	}
	if m["password"] != "too short" {
		t.Errorf("expected 'too short' for password, got %q", m["password"])
	}
	if _, ok := m[""]; ok {
		t.Error("empty-field entry should be skipped")
	}
}

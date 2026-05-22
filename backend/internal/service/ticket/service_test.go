package ticket

import (
	"testing"
	"time"

	domainTicket "github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
)

func TestValidateTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    domainTicket.Status
		to      domainTicket.Status
		wantErr bool
	}{
		{name: "OPEN -> IN_PROGRESS", from: domainTicket.StatusOpen, to: domainTicket.StatusInProgress, wantErr: false},
		{name: "IN_PROGRESS -> ESCALATED", from: domainTicket.StatusInProgress, to: domainTicket.StatusEscalated, wantErr: false},
		{name: "IN_PROGRESS -> FALSE_POSITIVE", from: domainTicket.StatusInProgress, to: domainTicket.StatusFalsePositive, wantErr: false},
		{name: "ESCALATED -> INVESTIGATING", from: domainTicket.StatusEscalated, to: domainTicket.StatusInvestigating, wantErr: false},
		{name: "INVESTIGATING -> RESOLVED", from: domainTicket.StatusInvestigating, to: domainTicket.StatusResolved, wantErr: false},
		{name: "INVESTIGATING -> FALSE_POSITIVE", from: domainTicket.StatusInvestigating, to: domainTicket.StatusFalsePositive, wantErr: false},

		// Invalid transitions
		{name: "OPEN -> RESOLVED (skip)", from: domainTicket.StatusOpen, to: domainTicket.StatusResolved, wantErr: true},
		{name: "OPEN -> ESCALATED (skip)", from: domainTicket.StatusOpen, to: domainTicket.StatusEscalated, wantErr: true},
		{name: "RESOLVED -> OPEN (backward)", from: domainTicket.StatusResolved, to: domainTicket.StatusOpen, wantErr: true},
		{name: "FALSE_POSITIVE -> IN_PROGRESS", from: domainTicket.StatusFalsePositive, to: domainTicket.StatusInProgress, wantErr: true},
		{name: "ESCALATED -> RESOLVED (skip L2)", from: domainTicket.StatusEscalated, to: domainTicket.StatusResolved, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTransition(tt.from, tt.to)
			if tt.wantErr && err == nil {
				t.Error("expected transition error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected allowed transition, got: %v", err)
			}
		})
	}
}

func TestBuildAnalyzeGoURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"  ", ""},
		{"http://ai-engine:5000", "http://ai-engine:5000/api/v1/analyze/go"},
		{"http://ai-engine:5000/", "http://ai-engine:5000/api/v1/analyze/go"},
		{"http://ai-engine:5000/api/v1", "http://ai-engine:5000/api/v1/analyze/go"},
		{"http://ai-engine:5000/api/v1/analyze", "http://ai-engine:5000/api/v1/analyze/go"},
		{"http://ai-engine:5000/api/v1/analyze/go", "http://ai-engine:5000/api/v1/analyze/go"},
		{"http://ai-engine:5000/analyze", "http://ai-engine:5000/analyze/go"},
		{"http://ai-engine:5000/analyze/go", "http://ai-engine:5000/analyze/go"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := buildAnalyzeGoURL(tt.input)
			if got != tt.expected {
				t.Errorf("buildAnalyzeGoURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected *domainTicket.Severity
	}{
		{"low", ptr(domainTicket.SeverityLow)},
		{"LOW", ptr(domainTicket.SeverityLow)},
		{"  Medium ", ptr(domainTicket.SeverityMedium)},
		{"high", ptr(domainTicket.SeverityHigh)},
		{"critical", ptr(domainTicket.SeverityCritical)},
		{"CRITICAL", ptr(domainTicket.SeverityCritical)},
		{"unknown", nil},
		{"", nil},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseSeverity(tt.input)
			if tt.expected == nil && got != nil {
				t.Errorf("expected nil, got %v", *got)
			}
			if tt.expected != nil && (got == nil || *got != *tt.expected) {
				t.Errorf("expected %v, got %v", *tt.expected, got)
			}
		})
	}
}

func TestSeverityToRuleLevel(t *testing.T) {
	tests := []struct {
		name     string
		severity *domainTicket.Severity
		expected int
	}{
		{"nil severity", nil, 7},
		{"low", ptr(domainTicket.SeverityLow), 7},
		{"medium", ptr(domainTicket.SeverityMedium), 8},
		{"high", ptr(domainTicket.SeverityHigh), 10},
		{"critical", ptr(domainTicket.SeverityCritical), 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityToRuleLevel(tt.severity)
			if got != tt.expected {
				t.Errorf("severityToRuleLevel(%v) = %d, want %d", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestNormalizeResponseLanguage(t *testing.T) {
	tests := []struct {
		input    *string
		expected string
	}{
		{nil, "id"},
		{strp(""), "id"},
		{strp("id"), "id"},
		{strp("en"), "en"},
		{strp("EN"), "en"},
		{strp("fr"), "id"},
	}
	for _, tt := range tests {
		label := "<nil>"
		if tt.input != nil {
			label = *tt.input
		}
		t.Run(label, func(t *testing.T) {
			got := normalizeResponseLanguage(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeResponseLanguage(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseEngineTimestamp(t *testing.T) {
	fallback := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("empty returns fallback", func(t *testing.T) {
		got := parseEngineTimestamp("", fallback)
		if !got.Equal(fallback) {
			t.Errorf("expected fallback, got %v", got)
		}
	})

	t.Run("RFC3339 parses correctly", func(t *testing.T) {
		got := parseEngineTimestamp("2026-06-15T10:30:00Z", fallback)
		expected := time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC)
		if !got.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("space-separated format", func(t *testing.T) {
		got := parseEngineTimestamp("2026-06-15 10:30:00", fallback)
		expected := time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC)
		if !got.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("garbage returns fallback", func(t *testing.T) {
		got := parseEngineTimestamp("not-a-timestamp", fallback)
		if !got.Equal(fallback) {
			t.Errorf("expected fallback, got %v", got)
		}
	})
}

func TestBuildRecommendationInputs(t *testing.T) {
	actions := []analyzeGoRecommendedAction{
		{Priority: 1, Action: "Block IP", Reason: "Known attacker"},
		{Priority: 0, Action: "Monitor traffic", Reason: "Suspicious"}, // priority 0 -> idx+1
		{Action: "  ", Reason: "Should be skipped"},                    // blank action
	}

	result := buildRecommendationInputs(actions)
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
	if result[0].Priority != 1 || result[0].Action != "Block IP" {
		t.Errorf("unexpected first result: %+v", result[0])
	}
	// second item had priority=0, so it should become idx+1=2
	if result[1].Priority != 2 || result[1].Action != "Monitor traffic" {
		t.Errorf("unexpected second result: %+v", result[1])
	}
}

func TestExtractMitreTechniqueIDs(t *testing.T) {
	attacks := []analyzeGoMitreAttack{
		{TechniqueID: "T1059"},
		{TechniqueID: "T1059"}, // duplicate
		{TechniqueID: ""},      // empty
		{TechniqueID: "T1548"},
	}

	result := extractMitreTechniqueIDs(attacks)
	if len(result) != 2 {
		t.Fatalf("expected 2 unique IDs, got %d: %v", len(result), result)
	}
	if result[0] != "T1059" || result[1] != "T1548" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "hello", "world"); got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
	if got := firstNonEmpty("", "", ""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
	if got := firstNonEmpty("first"); got != "first" {
		t.Errorf("expected 'first', got %q", got)
	}
}

func TestStringPtrOrNil(t *testing.T) {
	if got := stringPtrOrNil(""); got != nil {
		t.Error("expected nil for empty string")
	}
	if got := stringPtrOrNil("  "); got != nil {
		t.Error("expected nil for whitespace")
	}
	if got := stringPtrOrNil("hello"); got == nil || *got != "hello" {
		t.Errorf("expected 'hello', got %v", got)
	}
}

func TestValueOrEmpty(t *testing.T) {
	if got := valueOrEmpty(nil); got != "" {
		t.Errorf("expected empty for nil, got %q", got)
	}
	s := "test"
	if got := valueOrEmpty(&s); got != "test" {
		t.Errorf("expected 'test', got %q", got)
	}
}

func ptr(s domainTicket.Severity) *domainTicket.Severity {
	return &s
}

func strp(s string) *string {
	return &s
}

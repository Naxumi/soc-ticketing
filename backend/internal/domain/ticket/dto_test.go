package ticket

import (
	"errors"
	"testing"

	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

func TestListTicketsQueryFromStrings_Defaults(t *testing.T) {
	q, err := ListTicketsQueryFromStrings("", "", "", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Page != 1 {
		t.Errorf("expected default page=1, got %d", q.Page)
	}
	if q.Limit != 10 {
		t.Errorf("expected default limit=10, got %d", q.Limit)
	}
}

func TestListTicketsQueryFromStrings_CustomValues(t *testing.T) {
	q, err := ListTicketsQueryFromStrings("3", "25", "OPEN", "high", "", "active")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Page != 3 {
		t.Errorf("expected page=3, got %d", q.Page)
	}
	if q.Limit != 25 {
		t.Errorf("expected limit=25, got %d", q.Limit)
	}
	if q.Status == nil || *q.Status != StatusOpen {
		t.Errorf("expected status=OPEN, got %v", q.Status)
	}
	if q.Severity == nil || *q.Severity != SeverityHigh {
		t.Errorf("expected severity=high, got %v", q.Severity)
	}
	if q.Tab == nil || *q.Tab != TicketTabActive {
		t.Errorf("expected tab=active, got %v", q.Tab)
	}
}

func TestListTicketsQueryFromStrings_InvalidPage(t *testing.T) {
	_, err := ListTicketsQueryFromStrings("abc", "", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for non-integer page")
	}
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
}

func TestListTicketsQueryFromStrings_InvalidLimit(t *testing.T) {
	_, err := ListTicketsQueryFromStrings("1", "xyz", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for non-integer limit")
	}
}

func TestListTicketsQuery_Validate(t *testing.T) {
	tests := []struct {
		name    string
		q       ListTicketsQuery
		wantErr bool
		field   string
	}{
		{
			name:    "valid defaults",
			q:       ListTicketsQuery{Page: 1, Limit: 10},
			wantErr: false,
		},
		{
			name:    "page < 1",
			q:       ListTicketsQuery{Page: 0, Limit: 10},
			wantErr: true,
			field:   "page",
		},
		{
			name:    "limit < 1",
			q:       ListTicketsQuery{Page: 1, Limit: 0},
			wantErr: true,
			field:   "limit",
		},
		{
			name:    "limit > 100",
			q:       ListTicketsQuery{Page: 1, Limit: 200},
			wantErr: true,
			field:   "limit",
		},
		{
			name:    "invalid severity",
			q:       ListTicketsQuery{Page: 1, Limit: 10, Severity: sevPtr("banana")},
			wantErr: true,
			field:   "severity",
		},
		{
			name:    "valid severity",
			q:       ListTicketsQuery{Page: 1, Limit: 10, Severity: sevPtr(string(SeverityCritical))},
			wantErr: false,
		},
		{
			name:    "invalid assignee_id",
			q:       ListTicketsQuery{Page: 1, Limit: 10, AssigneeID: strPtr("not-a-uuid")},
			wantErr: true,
			field:   "assignee_id",
		},
		{
			name:    "valid assignee_id",
			q:       ListTicketsQuery{Page: 1, Limit: 10, AssigneeID: strPtr("550e8400-e29b-41d4-a716-446655440000")},
			wantErr: false,
		},
		{
			name:    "invalid tab",
			q:       ListTicketsQuery{Page: 1, Limit: 10, Tab: tabPtr("invalid")},
			wantErr: true,
			field:   "tab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.q.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tt.wantErr && tt.field != "" {
				var verrs validator.ValidationErrors
				if errors.As(err, &verrs) {
					found := false
					for _, ve := range verrs {
						if ve.Field == tt.field {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected validation error for field %q, got %v", tt.field, verrs)
					}
				}
			}
		})
	}
}

func TestUpdateStatusRequest_Validate(t *testing.T) {
	validUUID := "550e8400-e29b-41d4-a716-446655440000"

	tests := []struct {
		name    string
		req     UpdateStatusRequest
		wantErr bool
	}{
		{
			name:    "valid request",
			req:     UpdateStatusRequest{Status: StatusInProgress, AssigneeID: &validUUID, Note: "investigating"},
			wantErr: false,
		},
		{
			name:    "invalid status",
			req:     UpdateStatusRequest{Status: "INVALID", AssigneeID: &validUUID, Note: "note"},
			wantErr: true,
		},
		{
			name:    "missing assignee",
			req:     UpdateStatusRequest{Status: StatusInProgress, Note: "note"},
			wantErr: true,
		},
		{
			name:    "missing note",
			req:     UpdateStatusRequest{Status: StatusInProgress, AssigneeID: &validUUID, Note: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func sevPtr(s string) *Severity {
	sev := Severity(s)
	return &sev
}

func strPtr(s string) *string {
	return &s
}

func tabPtr(s string) *TicketTab {
	tab := TicketTab(s)
	return &tab
}

package report

import (
	"strconv"
	"strings"
	"time"

	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

// TimeWindow represents an inclusive time range in UTC.
// Used for reporting/export.
type TimeWindow struct {
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	Range string    `json:"range"`
}

type ExportTicketsQuery struct {
	Window     TimeWindow
	Status     *ticket.Status
	Severity   *ticket.Severity
	AssigneeID *string
	Limit      int
}

func ExportTicketsQueryFromStrings(rangeStr, fromStr, toStr, statusStr, severityStr, assigneeIDStr, limitStr string, now time.Time) (ExportTicketsQuery, error) {
	// Reuse ticket filter parsing/validation (status/severity/assignee).
	qf, err := ticket.ListTicketsQueryFromStrings("1", "10", statusStr, severityStr, assigneeIDStr, "")
	if err != nil {
		return ExportTicketsQuery{}, err
	}

	w, err := timeWindowFromStrings(rangeStr, fromStr, toStr, now.UTC())
	if err != nil {
		return ExportTicketsQuery{}, err
	}

	limit := 1000
	if strings.TrimSpace(limitStr) != "" {
		v, err := strconv.Atoi(strings.TrimSpace(limitStr))
		if err != nil {
			return ExportTicketsQuery{}, validator.ValidationErrors{{Field: "limit", Message: "limit must be an integer"}}
		}
		limit = v
	}

	q := ExportTicketsQuery{
		Window:     w,
		Status:     qf.Status,
		Severity:   qf.Severity,
		AssigneeID: qf.AssigneeID,
		Limit:      limit,
	}
	if err := q.Validate(); err != nil {
		return ExportTicketsQuery{}, err
	}
	return q, nil
}

func (q ExportTicketsQuery) Validate() error {
	var errs validator.ValidationErrors
	if q.Window.From.IsZero() {
		errs = append(errs, validator.ValidationError{Field: "from", Message: "from is required"})
	}
	if q.Window.To.IsZero() {
		errs = append(errs, validator.ValidationError{Field: "to", Message: "to is required"})
	}
	if !q.Window.From.IsZero() && !q.Window.To.IsZero() && q.Window.From.After(q.Window.To) {
		errs = append(errs, validator.ValidationError{Field: "from", Message: "from must be <= to"})
	}
	if q.Limit < 1 {
		errs = append(errs, validator.ValidationError{Field: "limit", Message: "limit must be >= 1"})
	} else if q.Limit > 10000 {
		errs = append(errs, validator.ValidationError{Field: "limit", Message: "limit must be <= 10000"})
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func timeWindowFromStrings(rangeStr, fromStr, toStr string, now time.Time) (TimeWindow, error) {
	rangeStr = strings.TrimSpace(rangeStr)
	fromStr = strings.TrimSpace(fromStr)
	toStr = strings.TrimSpace(toStr)

	// If from/to are provided, they win.
	if fromStr != "" || toStr != "" {
		if fromStr == "" || toStr == "" {
			return TimeWindow{}, validator.ValidationErrors{{Field: "from", Message: "from and to must be provided together"}}
		}
		from, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return TimeWindow{}, validator.ValidationErrors{{Field: "from", Message: "from must be RFC3339"}}
		}
		to, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			return TimeWindow{}, validator.ValidationErrors{{Field: "to", Message: "to must be RFC3339"}}
		}
		return TimeWindow{From: from.UTC(), To: to.UTC(), Range: rangeStr}, nil
	}

	// Default range.
	if rangeStr == "" {
		rangeStr = "7d"
	}

	dur, err := parseRange(rangeStr)
	if err != nil {
		return TimeWindow{}, err
	}
	to := now.UTC()
	from := now.Add(-dur)
	return TimeWindow{From: from.UTC(), To: to.UTC(), Range: rangeStr}, nil
}

func parseRange(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, validator.ValidationErrors{{Field: "range", Message: "range is required"}}
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return 0, validator.ValidationErrors{{Field: "range", Message: "range must be > 0"}}
		}
		return d, nil
	}

	// Support day shorthand like 7d.
	if strings.HasSuffix(s, "d") {
		nStr := strings.TrimSuffix(s, "d")
		n, err := strconv.Atoi(nStr)
		if err != nil {
			return 0, validator.ValidationErrors{{Field: "range", Message: "range must be like 24h or 7d"}}
		}
		if n <= 0 {
			return 0, validator.ValidationErrors{{Field: "range", Message: "range must be > 0"}}
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	return 0, validator.ValidationErrors{{Field: "range", Message: "range must be like 24h or 7d"}}
}

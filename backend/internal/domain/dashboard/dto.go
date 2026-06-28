package dashboard

import (
	"strconv"
	"strings"
	"time"

	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

// TimeWindow represents an inclusive time range in UTC.
// It is primarily used for "activity" metrics (e.g., tickets created in window).
// Backlog metrics can be computed independently of this window.
type TimeWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Range is the original requested range (if any), e.g. "24h" or "7d".
	Range string `json:"range"`
}

type Query struct {
	Window TimeWindow
	// RecentLimit controls how many recent tickets are returned.
	RecentLimit int
}

func QueryFromStrings(rangeStr, fromStr, toStr, recentLimitStr string, now time.Time) (Query, error) {
	now = now.UTC()

	limit := 10
	if strings.TrimSpace(recentLimitStr) != "" {
		v, err := strconv.Atoi(strings.TrimSpace(recentLimitStr))
		if err != nil {
			return Query{}, validator.ValidationErrors{{Field: "recent_limit", Message: "recent_limit must be an integer"}}
		}
		limit = v
	}

	w, err := timeWindowFromStrings(rangeStr, fromStr, toStr, now)
	if err != nil {
		return Query{}, err
	}

	q := Query{Window: w, RecentLimit: limit}
	if err := q.Validate(); err != nil {
		return Query{}, err
	}
	return q, nil
}

func (q Query) Validate() error {
	var errs validator.ValidationErrors
	if q.RecentLimit < 1 {
		errs = append(errs, validator.ValidationError{Field: "recent_limit", Message: "recent_limit must be >= 1"})
	} else if q.RecentLimit > 50 {
		errs = append(errs, validator.ValidationError{Field: "recent_limit", Message: "recent_limit must be <= 50"})
	}
	if q.Window.From.IsZero() {
		errs = append(errs, validator.ValidationError{Field: "from", Message: "from is required"})
	}
	if q.Window.To.IsZero() {
		errs = append(errs, validator.ValidationError{Field: "to", Message: "to is required"})
	}
	if !q.Window.From.IsZero() && !q.Window.To.IsZero() && q.Window.From.After(q.Window.To) {
		errs = append(errs, validator.ValidationError{Field: "from", Message: "from must be <= to"})
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
		rangeStr = "24h"
	}

	dur, err := parseRange(rangeStr)
	if err != nil {
		return TimeWindow{}, err
	}
	to := now
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

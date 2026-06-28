package dashboard

import (
	"context"
	"sort"
	"time"

	"github.com/naxumi/soc-ticketing/internal/domain/dashboard"
	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

type Service struct {
	repo dashboard.Repository
}

func New(repo dashboard.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Get(ctx context.Context, userID string, role string, q dashboard.Query) (dashboard.Response, error) {
	if err := q.Validate(); err != nil {
		return dashboard.Response{}, err
	}

	r := user.Role(role)
	if !isValidRole(r) {
		return dashboard.Response{}, validator.ValidationErrors{{Field: "role", Message: "invalid role"}}
	}

	unread, err := s.repo.CountUnreadNotifications(ctx, userID)
	if err != nil {
		return dashboard.Response{}, err
	}

	var backlogByStatus []dashboard.StatusCount
	var myByStatus []dashboard.StatusCount
	var backlogBySeverity []dashboard.StringCount
	var createdInWindow int64
	var createdBySeverityInWindow []dashboard.StringCount
	var recents []dashboard.RecentTicket

	if r == user.RoleSOCManager {
		backlogByStatus, err = s.repo.CountTicketsByStatus(ctx, nil)
		if err != nil {
			return dashboard.Response{}, err
		}
		myByStatus, err = s.repo.CountTicketsByStatus(ctx, &userID)
		if err != nil {
			return dashboard.Response{}, err
		}
		backlogBySeverity, err = s.repo.CountTicketsBySeverity(ctx)
		if err != nil {
			return dashboard.Response{}, err
		}
		createdInWindow, err = s.repo.CountTicketsCreatedInWindow(ctx, q.Window.From, q.Window.To)
		if err != nil {
			return dashboard.Response{}, err
		}
		createdBySeverityInWindow, err = s.repo.CountTicketsCreatedBySeverityInWindow(ctx, q.Window.From, q.Window.To)
		if err != nil {
			return dashboard.Response{}, err
		}
		recents, err = s.repo.ListRecentTicketsInWindow(ctx, q.Window.From, q.Window.To, q.RecentLimit)
		if err != nil {
			return dashboard.Response{}, err
		}
	} else {
		statuses := dashboardStatusesForRole(r)
		scope := dashboard.TicketScopeFilter{Statuses: statuses, UserID: &userID}
		if r == user.RoleL1Analyst {
			scope.AllowOpenForAll = true
		}
		if r == user.RoleL2Analyst {
			scope.AllowEscalatedForAll = true
		}

		backlogByStatus, err = s.repo.CountTicketsByStatusScoped(ctx, scope)
		if err != nil {
			return dashboard.Response{}, err
		}
		backlogBySeverity, err = s.repo.CountTicketsBySeverityScoped(ctx, scope)
		if err != nil {
			return dashboard.Response{}, err
		}
		createdInWindow, err = s.repo.CountTicketsCreatedInWindowScoped(ctx, q.Window.From, q.Window.To, scope)
		if err != nil {
			return dashboard.Response{}, err
		}
		createdBySeverityInWindow, err = s.repo.CountTicketsCreatedBySeverityInWindowScoped(ctx, q.Window.From, q.Window.To, scope)
		if err != nil {
			return dashboard.Response{}, err
		}
		recents, err = s.repo.ListRecentTicketsInWindowScoped(ctx, q.Window.From, q.Window.To, scope, q.RecentLimit)
		if err != nil {
			return dashboard.Response{}, err
		}

		myScope := scope
		myScope.AllowOpenForAll = false
		myScope.AllowEscalatedForAll = false
		myByStatus, err = s.repo.CountTicketsByStatusScoped(ctx, myScope)
		if err != nil {
			return dashboard.Response{}, err
		}
	}
	recentOut := make([]dashboard.TicketListItem, 0, len(recents))
	for _, t := range recents {
		recentOut = append(recentOut, dashboard.TicketListItem{
			ID:             t.ID,
			TicketNumber:   t.TicketNumber,
			SourceIP:       t.SourceIP,
			AttackRuleID:   t.AttackRuleID,
			ThreatCategory: t.ThreatCategory,
			ThreatType:     t.ThreatType,
			Severity:       t.Severity,
			Status:         t.Status,
			FirstSeen:      t.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:       t.LastSeen.UTC().Format(time.RFC3339),
			RawLogCount:    t.RawLogCount,
		})
	}

	out := dashboard.Response{
		Window:              q.Window,
		Role:                string(r),
		UnreadNotifications: unread,
		Tickets: dashboard.TicketsSection{
			BacklogByStatus:           toStatusMap(backlogByStatus),
			BacklogBySeverity:         toStringMap(backlogBySeverity),
			MyByStatus:                toStatusMap(myByStatus),
			CreatedInWindow:           createdInWindow,
			CreatedBySeverityInWindow: toStringMap(createdBySeverityInWindow),
			RecentInWindow:            recentOut,
		},
	}

	now := time.Now().UTC()
	out.GeneratedAtTime = now
	out.GeneratedAtUnix = now.Unix()
	out.GeneratedAt = now.Format(time.RFC3339)

	// Role-specific focus widgets.
	switch r {
	case user.RoleL1Analyst:
		unassignedOpen, err := s.repo.CountUnassignedActive(ctx, []ticket.Status{ticket.StatusOpen})
		if err != nil {
			return dashboard.Response{}, err
		}
		openHighCritical, err := s.repo.CountTicketsByStatusAndSeverities(ctx, ticket.StatusOpen, []ticket.Severity{ticket.SeverityHigh, ticket.SeverityCritical})
		if err != nil {
			return dashboard.Response{}, err
		}
		out.Focus = &dashboard.FocusSection{L1: &dashboard.L1Focus{
			UnassignedOpen:   unassignedOpen,
			OpenHighCritical: openHighCritical,
			MyInProgress:     out.Tickets.MyByStatus[ticket.StatusInProgress],
		}}
	case user.RoleL2Analyst:
		l2Scope := dashboard.TicketScopeFilter{Statuses: dashboardStatusesForRole(r), UserID: &userID, AllowEscalatedForAll: true}
		unassignedEscOrInv, err := s.repo.CountUnassignedActiveScoped(ctx, []ticket.Status{ticket.StatusEscalated, ticket.StatusInvestigating}, l2Scope)
		if err != nil {
			return dashboard.Response{}, err
		}
		out.Focus = &dashboard.FocusSection{L2: &dashboard.L2Focus{
			Escalated:                          out.Tickets.BacklogByStatus[ticket.StatusEscalated],
			Investigating:                      out.Tickets.BacklogByStatus[ticket.StatusInvestigating],
			UnassignedEscalatedOrInvestigating: unassignedEscOrInv,
			MyInvestigating:                    out.Tickets.MyByStatus[ticket.StatusInvestigating],
		}}
	}

	if r == user.RoleSOCManager {
		active := []ticket.Status{ticket.StatusOpen, ticket.StatusInProgress, ticket.StatusEscalated, ticket.StatusInvestigating}
		teamRows, err := s.repo.ListTeamActiveByAssigneeAndStatus(ctx, active)
		if err != nil {
			return dashboard.Response{}, err
		}
		unassigned, err := s.repo.CountUnassignedActive(ctx, active)
		if err != nil {
			return dashboard.Response{}, err
		}

		assignees := buildAssigneeWorkloads(teamRows)
		// Stable ordering for UI.
		sort.Slice(assignees, func(i, j int) bool {
			if assignees[i].TotalActive != assignees[j].TotalActive {
				return assignees[i].TotalActive > assignees[j].TotalActive
			}
			return assignees[i].FullName < assignees[j].FullName
		})

		out.Team = &dashboard.TeamSection{UnassignedActive: unassigned, Assignees: assignees}
	}

	return out, nil
}

func dashboardStatusesForRole(role user.Role) []ticket.Status {
	switch role {
	case user.RoleL1Analyst:
		return []ticket.Status{ticket.StatusOpen, ticket.StatusInProgress, ticket.StatusEscalated, ticket.StatusInvestigating, ticket.StatusFalsePositive, ticket.StatusResolved}
	case user.RoleL2Analyst:
		return []ticket.Status{ticket.StatusEscalated, ticket.StatusInvestigating, ticket.StatusFalsePositive, ticket.StatusResolved}
	default:
		return []ticket.Status{ticket.StatusOpen, ticket.StatusInProgress, ticket.StatusEscalated, ticket.StatusInvestigating, ticket.StatusFalsePositive, ticket.StatusResolved}
	}
}

func isValidRole(r user.Role) bool {
	switch r {
	case user.RoleL1Analyst, user.RoleL2Analyst, user.RoleSOCManager:
		return true
	default:
		return false
	}
}

func toStatusMap(rows []dashboard.StatusCount) map[ticket.Status]int64 {
	out := make(map[ticket.Status]int64)
	for _, r := range rows {
		out[r.Status] = r.Count
	}
	// Ensure known statuses exist with 0 (helps frontend).
	known := []ticket.Status{
		ticket.StatusOpen,
		ticket.StatusInProgress,
		ticket.StatusEscalated,
		ticket.StatusInvestigating,
		ticket.StatusFalsePositive,
		ticket.StatusResolved,
	}
	for _, st := range known {
		if _, ok := out[st]; !ok {
			out[st] = 0
		}
	}
	return out
}

func toStringMap(rows []dashboard.StringCount) map[string]int64 {
	out := make(map[string]int64)
	for _, r := range rows {
		out[r.Key] = r.Count
	}
	return out
}

func buildAssigneeWorkloads(rows []dashboard.TeamStatusCount) []dashboard.AssigneeWorkload {
	byUser := make(map[string]*dashboard.AssigneeWorkload)
	for _, r := range rows {
		w := byUser[r.UserID]
		if w == nil {
			w = &dashboard.AssigneeWorkload{
				UserID:         r.UserID,
				FullName:       r.FullName,
				Username:       r.Username,
				Role:           r.Role,
				ActiveByStatus: make(map[ticket.Status]int64),
			}
			byUser[r.UserID] = w
		}
		w.ActiveByStatus[r.Status] += r.Count
		w.TotalActive += r.Count
	}

	out := make([]dashboard.AssigneeWorkload, 0, len(byUser))
	for _, w := range byUser {
		// Ensure keys exist for active statuses.
		for _, st := range []ticket.Status{ticket.StatusOpen, ticket.StatusInProgress, ticket.StatusEscalated, ticket.StatusInvestigating} {
			if _, ok := w.ActiveByStatus[st]; !ok {
				w.ActiveByStatus[st] = 0
			}
		}
		out = append(out, *w)
	}
	return out
}

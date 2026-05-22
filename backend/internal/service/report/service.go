package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phpdave11/gofpdf"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/report"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
)

type Service struct {
	repo report.Repository
	tix  ticket.Repository
}

func New(repo report.Repository, tix ticket.Repository) *Service {
	return &Service{repo: repo, tix: tix}
}

func (s *Service) ExportTicketsCSV(ctx context.Context, q report.ExportTicketsQuery, w io.Writer) error {
	ids, err := s.repo.ListTicketIDsForExport(ctx, q)
	if err != nil {
		return err
	}

	cw := csv.NewWriter(w)
	// Header
	if err := cw.Write([]string{
		"ticket_id",
		"ticket_number",
		"source_ip",
		"attack_rule_id",
		"threat_category",
		"threat_type",
		"severity",
		"status",
		"assignee_id",
		"first_seen",
		"last_seen",
		"raw_log_count",
		"payload_first_json",
		"payload_last_json",
		"payload_sample_json",
		"created_at",
		"updated_at",
		"analysis_model_name",
		"analysis_summary",
		"analysis_detailed_analysis",
		"analysis_attack_vector",
		"analysis_potential_impact",
		"analysis_confidence_score",
		"analysis_processing_time_ms",
		"analysis_created_at",
		"recommendations_json",
		"iocs_json",
		"audit_logs_json",
		"raw_logs_json",
	}); err != nil {
		return err
	}

	for _, id := range ids {
		detail, err := s.tix.GetDetail(ctx, id)
		if err != nil {
			return err
		}

		sev := ""
		if detail.Ticket.Severity != nil {
			sev = string(*detail.Ticket.Severity)
		}

		analysisModel := ""
		analysisSummary := ""
		analysisDetailed := ""
		analysisAttack := ""
		analysisImpact := ""
		analysisConfidence := ""
		analysisProcessing := ""
		analysisCreated := ""
		if detail.Analysis != nil {
			analysisModel = detail.Analysis.ModelName
			if detail.Analysis.Summary != nil {
				analysisSummary = *detail.Analysis.Summary
			}
			if detail.Analysis.DetailedAnalysis != nil {
				analysisDetailed = *detail.Analysis.DetailedAnalysis
			}
			if detail.Analysis.AttackVector != nil {
				analysisAttack = *detail.Analysis.AttackVector
			}
			if detail.Analysis.PotentialImpact != nil {
				analysisImpact = *detail.Analysis.PotentialImpact
			}
			if detail.Analysis.ConfidenceScore != nil {
				analysisConfidence = strconv.FormatFloat(*detail.Analysis.ConfidenceScore, 'f', -1, 64)
			}
			if detail.Analysis.ProcessingTimeMs != nil {
				analysisProcessing = strconv.FormatFloat(*detail.Analysis.ProcessingTimeMs, 'f', -1, 64)
			}
			analysisCreated = detail.Analysis.CreatedAt.UTC().Format(time.RFC3339)
		}

		type recExport struct {
			Priority int     `json:"priority"`
			Action   string  `json:"action"`
			Reason   *string `json:"reason,omitempty"`
		}
		recsOut := make([]recExport, 0, len(detail.Recommendations))
		for _, r := range detail.Recommendations {
			recsOut = append(recsOut, recExport{Priority: r.Priority, Action: r.Action, Reason: r.Reason})
		}

		type iocExport struct {
			IOCType   string `json:"ioc_type"`
			IOCValue  string `json:"ioc_value"`
			CreatedAt string `json:"created_at"`
		}
		iocsOut := make([]iocExport, 0, len(detail.IOCs))
		for _, i := range detail.IOCs {
			iocsOut = append(iocsOut, iocExport{IOCType: i.IOCType, IOCValue: i.IOCValue, CreatedAt: i.CreatedAt.UTC().Format(time.RFC3339)})
		}

		type auditExport struct {
			Action    string  `json:"action"`
			Note      *string `json:"note,omitempty"`
			CreatedAt string  `json:"created_at"`
		}
		logsOut := make([]auditExport, 0, len(detail.AuditLogs))
		for _, l := range detail.AuditLogs {
			logsOut = append(logsOut, auditExport{Action: l.Action, Note: l.Note, CreatedAt: l.CreatedAt.UTC().Format(time.RFC3339)})
		}

		recJSON, _ := json.Marshal(recsOut)
		iocsJSON, _ := json.Marshal(iocsOut)
		logsJSON, _ := json.Marshal(logsOut)

		type rawLogExport struct {
			WazuhEventID *string         `json:"wazuh_event_id,omitempty"`
			SourceIP     string          `json:"source_ip"`
			AttackRuleID string          `json:"attack_rule_id"`
			EventTime    string          `json:"event_timestamp"`
			RawPayload   json.RawMessage `json:"raw_payload"`
			CreatedAt    string          `json:"created_at"`
		}
		rawLogsOut := make([]rawLogExport, 0, len(detail.RawLogs))
		for _, rl := range detail.RawLogs {
			rawLogsOut = append(rawLogsOut, rawLogExport{
				WazuhEventID: rl.WazuhEventID,
				SourceIP:     rl.SourceIP,
				AttackRuleID: rl.AttackRuleID,
				EventTime:    rl.EventTime.UTC().Format(time.RFC3339),
				RawPayload:   rl.RawPayload,
				CreatedAt:    rl.CreatedAt.UTC().Format(time.RFC3339),
			})
		}
		rawLogsJSON, _ := json.Marshal(rawLogsOut)

		cat := ""
		if detail.Ticket.ThreatCategory != nil {
			cat = *detail.Ticket.ThreatCategory
		}
		typ := ""
		if detail.Ticket.ThreatType != nil {
			typ = *detail.Ticket.ThreatType
		}
		assignee := ""
		if detail.Ticket.AssigneeID != nil {
			assignee = *detail.Ticket.AssigneeID
		}

		if err := cw.Write([]string{
			detail.Ticket.ID,
			detail.Ticket.TicketNumber,
			detail.Ticket.SourceIP,
			detail.Ticket.AttackRuleID,
			cat,
			typ,
			sev,
			string(detail.Ticket.Status),
			assignee,
			detail.Ticket.FirstSeen.UTC().Format(time.RFC3339),
			detail.Ticket.LastSeen.UTC().Format(time.RFC3339),
			strconv.Itoa(detail.Ticket.RawLogCount),
			string(detail.Ticket.PayloadFirst),
			string(detail.Ticket.PayloadLast),
			string(detail.Ticket.PayloadSample),
			detail.Ticket.CreatedAt.UTC().Format(time.RFC3339),
			detail.Ticket.UpdatedAt.UTC().Format(time.RFC3339),
			analysisModel,
			analysisSummary,
			analysisDetailed,
			analysisAttack,
			analysisImpact,
			analysisConfidence,
			analysisProcessing,
			analysisCreated,
			string(recJSON),
			string(iocsJSON),
			string(logsJSON),
			string(rawLogsJSON),
		}); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

func (s *Service) ExportTicketsPDF(ctx context.Context, q report.ExportTicketsQuery) ([]byte, error) {
	ids, err := s.repo.ListTicketIDsForExport(ctx, q)
	if err != nil {
		return nil, err
	}

	details := make([]ticket.Detail, 0, len(ids))
	statusCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	var rawLogTotal int
	for _, id := range ids {
		detail, err := s.tix.GetDetail(ctx, id)
		if err != nil {
			return nil, err
		}
		details = append(details, detail)
		statusCounts[string(detail.Ticket.Status)]++
		if detail.Ticket.Severity != nil {
			severityCounts[string(*detail.Ticket.Severity)]++
		} else {
			severityCounts["unknown"]++
		}
		rawLogTotal += detail.Ticket.RawLogCount
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 16, 14)
	pdf.SetAutoPageBreak(true, 16)
	pdf.SetTitle("SOC Ticket Report", false)
	pdf.SetAuthor("SOC Ticketing System", false)
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(0, 6, "SOC Ticket Report", "", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, time.Now().UTC().Format(time.RFC3339), "", 0, "R", false, 0, "")
		pdf.Ln(8)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	// Cover page
	pdf.AddPage()
	writePDFTitle(pdf, "SOC Ticket Report")
	writePDFSection(pdf, "Report Window")
	writePDFKeyValue(pdf, "From", q.Window.From.UTC().Format(time.RFC3339))
	writePDFKeyValue(pdf, "To", q.Window.To.UTC().Format(time.RFC3339))
	if strings.TrimSpace(q.Window.Range) != "" {
		writePDFKeyValue(pdf, "Range", q.Window.Range)
	}
	writePDFKeyValue(pdf, "Limit", strconv.Itoa(q.Limit))
	statusFilter := "all"
	if q.Status != nil {
		statusFilter = string(*q.Status)
	}
	severityFilter := "all"
	if q.Severity != nil {
		severityFilter = string(*q.Severity)
	}
	assigneeFilter := "all"
	if q.AssigneeID != nil && strings.TrimSpace(*q.AssigneeID) != "" {
		assigneeFilter = *q.AssigneeID
	}
	writePDFKeyValue(pdf, "Filter: status", statusFilter)
	writePDFKeyValue(pdf, "Filter: severity", severityFilter)
	writePDFKeyValue(pdf, "Filter: assignee", assigneeFilter)

	writePDFSection(pdf, "Summary")
	writePDFKeyValue(pdf, "Tickets", strconv.Itoa(len(details)))
	writePDFKeyValue(pdf, "Raw logs (total)", strconv.Itoa(rawLogTotal))
	writePDFSubSection(pdf, "By status")
	for _, item := range sortedCountItems(statusCounts) {
		writePDFKeyValue(pdf, item.Key, strconv.Itoa(item.Value))
	}
	writePDFSubSection(pdf, "By severity")
	for _, item := range sortedCountItems(severityCounts) {
		writePDFKeyValue(pdf, item.Key, strconv.Itoa(item.Value))
	}

	for i, detail := range details {
		pdf.AddPage()
		writePDFSection(pdf, fmt.Sprintf("Ticket %d of %d", i+1, len(details)))
		writePDFKeyValue(pdf, "Ticket number", detail.Ticket.TicketNumber)
		writePDFKeyValue(pdf, "Ticket ID", detail.Ticket.ID)
		writePDFKeyValue(pdf, "Status", string(detail.Ticket.Status))
		if detail.Ticket.Severity != nil {
			writePDFKeyValue(pdf, "Severity", string(*detail.Ticket.Severity))
		}
		writePDFKeyValue(pdf, "Source IP", detail.Ticket.SourceIP)
		writePDFKeyValue(pdf, "Attack rule ID", detail.Ticket.AttackRuleID)
		if detail.Ticket.ThreatCategory != nil {
			writePDFKeyValue(pdf, "Threat category", *detail.Ticket.ThreatCategory)
		}
		if detail.Ticket.ThreatType != nil {
			writePDFKeyValue(pdf, "Threat type", *detail.Ticket.ThreatType)
		}
		if detail.Ticket.AssigneeID != nil {
			writePDFKeyValue(pdf, "Assignee", *detail.Ticket.AssigneeID)
		}
		writePDFKeyValue(pdf, "First seen", detail.Ticket.FirstSeen.UTC().Format(time.RFC3339))
		writePDFKeyValue(pdf, "Last seen", detail.Ticket.LastSeen.UTC().Format(time.RFC3339))
		writePDFKeyValue(pdf, "Raw log count", strconv.Itoa(detail.Ticket.RawLogCount))
		writePDFKeyValue(pdf, "Created at", detail.Ticket.CreatedAt.UTC().Format(time.RFC3339))
		writePDFKeyValue(pdf, "Updated at", detail.Ticket.UpdatedAt.UTC().Format(time.RFC3339))

		writePDFDivider(pdf)

		if detail.Analysis != nil {
			writePDFSection(pdf, "Analysis")
			writePDFKeyValue(pdf, "Model", detail.Analysis.ModelName)
			writePDFKeyValue(pdf, "Created", detail.Analysis.CreatedAt.UTC().Format(time.RFC3339))
			if detail.Analysis.ConfidenceScore != nil {
				writePDFKeyValue(pdf, "Confidence", strconv.FormatFloat(*detail.Analysis.ConfidenceScore, 'f', 2, 64))
			}
			if detail.Analysis.ProcessingTimeMs != nil {
				writePDFKeyValue(pdf, "Processing (ms)", strconv.FormatFloat(*detail.Analysis.ProcessingTimeMs, 'f', 2, 64))
			}
			if detail.Analysis.AttackVector != nil {
				writePDFKeyValue(pdf, "Attack vector", *detail.Analysis.AttackVector)
			}
			if detail.Analysis.PotentialImpact != nil {
				writePDFKeyValue(pdf, "Potential impact", *detail.Analysis.PotentialImpact)
			}
			if detail.Analysis.Summary != nil {
				writePDFSubSection(pdf, "Summary")
				writePDFParagraph(pdf, *detail.Analysis.Summary)
			}
			if detail.Analysis.DetailedAnalysis != nil {
				writePDFSubSection(pdf, "Detailed analysis")
				writePDFParagraph(pdf, *detail.Analysis.DetailedAnalysis)
			}
		}

		if len(detail.IOCs) > 0 {
			writePDFSection(pdf, "Indicators (IOCs)")
			items := make([]string, 0, len(detail.IOCs))
			for _, ioc := range detail.IOCs {
				items = append(items, fmt.Sprintf("%s: %s", ioc.IOCType, ioc.IOCValue))
			}
			writePDFList(pdf, items, 9)
		}

		if len(detail.Recommendations) > 0 {
			writePDFSection(pdf, "Recommendations")
			items := make([]string, 0, len(detail.Recommendations))
			for _, rec := range detail.Recommendations {
				line := fmt.Sprintf("[%d] %s", rec.Priority, rec.Action)
				if rec.Reason != nil && strings.TrimSpace(*rec.Reason) != "" {
					line = line + fmt.Sprintf(" (reason: %s)", *rec.Reason)
				}
				items = append(items, line)
			}
			writePDFList(pdf, items, 9)
		}

		if len(detail.AuditLogs) > 0 {
			writePDFSection(pdf, "Audit logs")
			limit := minInt(10, len(detail.AuditLogs))
			for idx := 0; idx < limit; idx++ {
				l := detail.AuditLogs[idx]
				note := ""
				if l.Note != nil {
					note = *l.Note
				}
				writePDFLine(pdf, fmt.Sprintf("%s | %s", l.CreatedAt.UTC().Format(time.RFC3339), l.Action), 9, true)
				if strings.TrimSpace(note) != "" {
					writePDFParagraph(pdf, note)
				}
			}
			if len(detail.AuditLogs) > limit {
				writePDFLine(pdf, fmt.Sprintf("... %d more audit logs omitted", len(detail.AuditLogs)-limit), 8, false)
			}
		}

		if len(detail.RawLogs) > 0 {
			writePDFSection(pdf, "Raw log samples")
			limit := minInt(3, len(detail.RawLogs))
			for idx := 0; idx < limit; idx++ {
				rl := detail.RawLogs[idx]
				writePDFLine(pdf, fmt.Sprintf("%s | %s | %s", rl.EventTime.UTC().Format(time.RFC3339), rl.SourceIP, rl.AttackRuleID), 8, true)
				writePDFParagraph(pdf, truncateText(string(rl.RawPayload), 800))
			}
			if len(detail.RawLogs) > limit {
				writePDFLine(pdf, fmt.Sprintf("... %d more raw logs omitted", len(detail.RawLogs)-limit), 8, false)
			}
		}
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writePDFTitle(pdf *gofpdf.Fpdf, text string) {
	writePDFLine(pdf, text, 20, true)
	writePDFLine(pdf, "", 6, false)
}

func writePDFSection(pdf *gofpdf.Fpdf, text string) {
	writePDFLine(pdf, text, 12, true)
}

func writePDFSubSection(pdf *gofpdf.Fpdf, text string) {
	writePDFLine(pdf, text, 10, true)
}

func writePDFKeyValue(pdf *gofpdf.Fpdf, key, value string) {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	labelWidth := 36.0
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(labelWidth, 5, key, "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5, value, "", "L", false)
}

func writePDFParagraph(pdf *gofpdf.Fpdf, text string) {
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5, text, "", "L", false)
}

func writePDFList(pdf *gofpdf.Fpdf, items []string, size float64) {
	for _, item := range items {
		writePDFLine(pdf, "- "+item, size, false)
	}
}

func writePDFDivider(pdf *gofpdf.Fpdf) {
	curY := pdf.GetY()
	left, _, right, _ := pdf.GetMargins()
	pageW, _ := pdf.GetPageSize()
	pdf.Line(left, curY+1, pageW-right, curY+1)
	pdf.Ln(3)
}

func writePDFLine(pdf *gofpdf.Fpdf, text string, size float64, bold bool) {
	style := ""
	if bold {
		style = "B"
	}
	pdf.SetFont("Helvetica", style, size)
	lineHeight := size + 2
	if lineHeight < 5 {
		lineHeight = 5
	}
	pdf.MultiCell(0, lineHeight, text, "", "L", false)
}

func truncateText(value string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	value = strings.TrimSpace(value)
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type countItem struct {
	Key   string
	Value int
}

func sortedCountItems(counts map[string]int) []countItem {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]countItem, 0, len(keys))
	for _, k := range keys {
		out = append(out, countItem{Key: k, Value: counts[k]})
	}
	return out
}

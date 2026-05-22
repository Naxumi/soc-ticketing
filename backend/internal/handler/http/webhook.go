package http

import (
	"encoding/json"
	"net/http"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/webhook"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/response"
)

type WebhookHandler struct {
	svc webhook.Service
}

func NewWebhookHandler(svc webhook.Service) *WebhookHandler {
	return &WebhookHandler{svc: svc}
}

func (h *WebhookHandler) IngestWazuh(w http.ResponseWriter, r *http.Request) {
	var req webhook.WazuhWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	res, err := h.svc.IngestWazuh(r.Context(), req)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Created(w, "Webhook processed", res)
}

func (h *WebhookHandler) IngestWazuhRawLogs(w http.ResponseWriter, r *http.Request) {
	var req webhook.WazuhRawLogBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	res, err := h.svc.IngestRawLogs(r.Context(), req)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Created(w, "Raw logs ingested", res)
}

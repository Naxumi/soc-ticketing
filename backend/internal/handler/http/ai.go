package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/naxumi/soc-ticketing/internal/handler/http/response"
)

type AIHandler struct {
	modelsURL string
	apiKey    string
	client    *http.Client
}

type ModelListResponse struct {
	Models []string `json:"models"`
}

func NewAIHandler(modelsURL string, analyzeURL string, apiKey string, timeout time.Duration) *AIHandler {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	resolvedModelsURL := strings.TrimSpace(modelsURL)
	if resolvedModelsURL == "" {
		resolvedModelsURL = buildModelsURL(analyzeURL)
	}

	return &AIHandler{
		modelsURL: resolvedModelsURL,
		apiKey:    strings.TrimSpace(apiKey),
		client:    &http.Client{Timeout: timeout},
	}
}

func (h *AIHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	if h.modelsURL == "" {
		response.ValidationError(w, map[string]string{"models_api_url": "models API URL is not configured"})
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.modelsURL, nil)
	if err != nil {
		response.InternalServerError(w, "Failed to build models request")
		return
	}

	req.Header.Set("Accept", "application/json")
	if h.apiKey != "" {
		req.Header.Set("X-API-Key", h.apiKey)
	}

	res, err := h.client.Do(req)
	if err != nil {
		response.InternalServerError(w, "Failed to fetch models")
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		response.InternalServerError(w, "Failed to read models response")
		return
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = "external models API returned non-success status"
		}
		response.ValidationError(w, map[string]string{"models_api": msg})
		return
	}

	if len(body) == 0 {
		response.Success(w, ModelListResponse{Models: []string{}})
		return
	}

	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		response.ValidationError(w, map[string]string{"models_api": "invalid response format from models API"})
		return
	}

	response.Success(w, ModelListResponse{Models: extractModelNames(payload)})
}

func buildModelsURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}

	path := strings.TrimRight(parsed.Path, "/")
	switch {
	case strings.HasSuffix(path, "/api/v1/analyze/go"):
		path = strings.TrimSuffix(path, "/api/v1/analyze/go")
	case strings.HasSuffix(path, "/api/v1/analyze"):
		path = strings.TrimSuffix(path, "/api/v1/analyze")
	case strings.HasSuffix(path, "/api/v1"):
		path = strings.TrimSuffix(path, "/api/v1")
	case strings.HasSuffix(path, "/analyze/go"):
		path = strings.TrimSuffix(path, "/analyze/go")
	case strings.HasSuffix(path, "/analyze"):
		path = strings.TrimSuffix(path, "/analyze")
	}

	path = strings.TrimRight(path, "/")
	parsed.Path = path + "/api/v1/models"
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

func extractModelNames(payload any) []string {
	seen := map[string]struct{}{}
	models := make([]string, 0)

	add := func(value string) {
		name := strings.TrimSpace(value)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		models = append(models, name)
	}

	var fromArray func([]any)
	fromArray = func(items []any) {
		for _, item := range items {
			switch v := item.(type) {
			case string:
				add(v)
			case map[string]any:
				if id, ok := v["id"].(string); ok {
					add(id)
					continue
				}
				if name, ok := v["name"].(string); ok {
					add(name)
					continue
				}
				if model, ok := v["model"].(string); ok {
					add(model)
					continue
				}
			}
		}
	}

	switch v := payload.(type) {
	case []any:
		fromArray(v)
	case map[string]any:
		if arr, ok := v["models"].([]any); ok {
			fromArray(arr)
		}
		if arr, ok := v["available_models"].([]any); ok {
			fromArray(arr)
		}
		if arr, ok := v["data"].([]any); ok {
			fromArray(arr)
		}
		if def, ok := v["default_model"].(string); ok {
			add(def)
		}
		if data, ok := v["data"].(map[string]any); ok {
			if arr, ok := data["models"].([]any); ok {
				fromArray(arr)
			}
			if arr, ok := data["available_models"].([]any); ok {
				fromArray(arr)
			}
			if arr, ok := data["data"].([]any); ok {
				fromArray(arr)
			}
		}
		if arr, ok := v["result"].([]any); ok {
			fromArray(arr)
		}
	}

	return models
}

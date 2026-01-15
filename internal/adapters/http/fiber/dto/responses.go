package dto

type SuccessResponse struct {
	Success bool   `json:"success"`           // "success" or "error"
	Message string `json:"message,omitempty"` // Optional message
	Data    any    `json:"data,omitempty"`    // Optional payload
}

type ErrorResponse struct {
	Success bool           `json:"success"`           // Always false for this DTO
	Type    string         `json:"type"`              // e.g., "VALIDATION", "INTERNAL", "NOT_FOUND"
	Message string         `json:"message"`           // Human-readable summary
	TraceID string         `json:"trace_id"`          // For support and logging correlation
	Details map[string]any `json:"details,omitempty"` // Contextual data (e.g., {"field": "email"})
}

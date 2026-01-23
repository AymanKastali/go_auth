package dto

type SuccessResponse struct {
	Message string `json:"message,omitempty" example:"humanized success message"`
	Data    any    `json:"data,omitempty"`
}

type ErrorResponse struct {
	Type    string         `json:"type" example:"VALIDATION"`
	Message string         `json:"message" example:"humanized error message"`
	TraceID string         `json:"trace_id" example:"req-12345"`
	Details map[string]any `json:"details,omitempty"`
}

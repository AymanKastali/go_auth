package dto

type SuccessResponse struct {
	Success bool   `json:"success"`           // "success" or "error"
	Message string `json:"message,omitempty"` // Optional message
	Data    any    `json:"data,omitempty"`    // Optional payload
}

type ErrorResponse struct {
	Kind    int    `json:"kind"`
	Success bool   `json:"success"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"` // For validation errors
}

package dto

//	type APIResponse struct {
//		Status  string `json:"status"`            // "success" or "error"
//		Message string `json:"message,omitempty"` // Optional message
//		Data    any    `json:"data,omitempty"`    // Optional payload
//		Errors  any    `json:"errors,omitempty"`  // Optional errors
//	}
type SuccessResponse struct {
	Success bool   `json:"success"`           // "success" or "error"
	Message string `json:"message,omitempty"` // Optional message
	Data    any    `json:"data,omitempty"`    // Optional payload
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"` // For validation errors
}

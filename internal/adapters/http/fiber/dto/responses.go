package dto

type APIResponse struct {
	Status  string `json:"status"`            // "success" or "error"
	Message string `json:"message,omitempty"` // Optional message
	Data    any    `json:"data,omitempty"`    // Optional payload
	Errors  any    `json:"errors,omitempty"`  // Optional errors
}

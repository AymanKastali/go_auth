package dto

type contextKey string

const (
	// ContextKey is the single source of truth for accessing the DTO in Fiber
	ContextKey contextKey = "app_context"
)

type RequestContext struct {
	RequestID  string
	DeviceID   string
	DeviceName string
	UserAgent  string
	IPAddress  string
}

type AuthContext struct {
	RequestContext
	UserID  string
	Roles   []string
	TokenID string
}

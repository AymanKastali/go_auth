package dto

type RequestContext struct {
	TraceID    string
	DeviceID   string
	DeviceName string
	UserAgent  string
	IPAddress  string
}

type AuthContext struct {
	TraceID  string
	UserID   string
	Roles    []string
	TokenID  string
	DeviceID string
}

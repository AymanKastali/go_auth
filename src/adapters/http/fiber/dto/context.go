package dto

type RequestContext struct {
	DeviceID   string
	DeviceName string
	UserAgent  string
	IPAddress  string
}

type AuthContext struct {
	UserID   string
	Roles    []string
	TokenID  string
	DeviceID string
}

package dto

type LoginInput struct {
	Email             string
	Password          string
	DeviceFingerprint string
	DeviceName        *string
	UserAgent         *string
	IPAddress         *string
}

type SessionRenewalInput struct {
	RefreshToken      string
	DeviceFingerprint string
}

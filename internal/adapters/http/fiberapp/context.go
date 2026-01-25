package fiberapp

import (
	"fmt"
	"log/slog"
)

// RequestContext carries request and user info
type RequestContext struct {
	// Request metadata
	requestID string
	userAgent string
	ipAddress string
	language  string

	// Authenticated user info
	userID    string
	roles     []string
	sessionID string

	// Logger (never nil)
	logger *slog.Logger
}

// Constructor
func NewRequestContext(
	requestID, userAgent, ipAddress, language string,
	logger *slog.Logger,
) *RequestContext {
	if logger == nil {
		logger = slog.Default()
	}
	return &RequestContext{
		requestID: requestID,
		userAgent: userAgent,
		ipAddress: ipAddress,
		language:  language,
		logger:    logger,
		roles:     []string{}, // ensure safe default
	}
}

// Safe Getters
func (rc *RequestContext) RequestID() string { return rc.requestID }
func (rc *RequestContext) UserAgent() string { return rc.userAgent }
func (rc *RequestContext) IPAddress() string { return rc.ipAddress }
func (rc *RequestContext) Language() string  { return rc.language }

func (rc *RequestContext) UserID() string { return rc.userID }
func (rc *RequestContext) Roles() []string {
	if rc.roles == nil {
		return []string{}
	}
	return rc.roles
}
func (rc *RequestContext) SessionID() string { return rc.sessionID }

func (rc *RequestContext) Logger() *slog.Logger { return rc.logger }

// Auth helpers
func (rc *RequestContext) IsAuthenticated() bool {
	return rc.userID != ""
}

func (rc *RequestContext) HasRole(role string) bool {
	for _, r := range rc.Roles() {
		if r == role {
			return true
		}
	}
	return false
}

// Setters (for middleware / auth layer)
func (rc *RequestContext) SetUser(userID, sessionID string, roles []string) {
	rc.userID = userID
	rc.sessionID = sessionID
	rc.roles = roles
}

// Fingerprint

// FingerprintString returns the combined raw fingerprint string
func (rc *RequestContext) FingerprintString() string {
	return fmt.Sprintf("%s|%s|%s", rc.userAgent, rc.ipAddress, rc.language)
}

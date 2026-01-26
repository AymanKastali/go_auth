package fiberapp

import (
	"context"
	"log/slog"
	"slices"

	"github.com/mssola/useragent"
)

type ctxKey struct{}

var requestCtxKey = &ctxKey{}

type DeviceMetadata struct {
	OS       string
	Platform string
	Browser  string
	Version  string
	IsMobile bool
	IsBot    bool
	Model    string
}

type RequestContext struct {
	requestID      string
	userAgent      string // Added to keep raw UA for fingerprinting
	ipAddress      string
	acceptLanguage string

	deviceMetadata DeviceMetadata

	userID    string
	sessionID string
	roles     []string

	logger *slog.Logger
}

// NewRequestContext now takes the raw UA string and parses it internally
func NewRequestContext(
	requestID string,
	ipAddress, acceptLanguage, uaRaw string,
	logger *slog.Logger,
) *RequestContext {
	if logger == nil {
		logger = slog.Default()
	}

	ua := useragent.New(uaRaw)
	browserName, browserVersion := ua.Browser()

	return &RequestContext{
		requestID:      requestID,
		userAgent:      uaRaw,
		ipAddress:      ipAddress,
		acceptLanguage: acceptLanguage,
		deviceMetadata: DeviceMetadata{
			OS:       ua.OS(),
			Platform: ua.Platform(),
			Browser:  browserName,
			Version:  browserVersion,
			IsMobile: ua.Mobile(),
			IsBot:    ua.Bot(),
			Model:    ua.Model(),
		},
		logger: logger,
		roles:  []string{},
	}
}

func GetRequestContext(ctx context.Context) *RequestContext {
	rc, ok := ctx.Value(requestCtxKey).(*RequestContext)
	if ok && rc != nil {
		return rc
	}
	return &RequestContext{
		requestID: "unknown",
		logger:    slog.Default(),
		roles:     []string{},
	}
}

// --- Getters ---

func (rc *RequestContext) RequestID() string      { return rc.requestID }
func (rc *RequestContext) IPAddress() string      { return rc.ipAddress }
func (rc *RequestContext) AcceptLanguage() string { return rc.acceptLanguage }
func (rc *RequestContext) UserAgent() string      { return rc.userAgent }

// Metadata Getters (Aligned with the struct)
func (rc *RequestContext) Device() DeviceMetadata { return rc.deviceMetadata }

// Auth Getters
func (rc *RequestContext) UserID() string           { return rc.userID }
func (rc *RequestContext) SessionID() string        { return rc.sessionID }
func (rc *RequestContext) Roles() []string          { return rc.roles }
func (rc *RequestContext) IsAuthenticated() bool    { return rc.userID != "" }
func (rc *RequestContext) HasRole(role string) bool { return slices.Contains(rc.roles, role) }
func (rc *RequestContext) Logger() *slog.Logger     { return rc.logger }

// Setters
func (rc *RequestContext) SetUser(userID, sessionID string, roles []string) {
	rc.userID = userID
	rc.sessionID = sessionID
	rc.roles = roles
}

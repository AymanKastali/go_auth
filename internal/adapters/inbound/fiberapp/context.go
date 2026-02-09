package fiberapp

import (
	"context"
	"errors"
	"go_auth/internal/application"
	"log/slog"

	"github.com/mssola/useragent"
)

var (
	ErrContextNotFound = errors.New("request context not found in context")
	ErrAppCtxNil       = errors.New("application context is not initialized")
)

type ctxKey struct{}

var requestCtxKey = ctxKey{}

// RequestContext acts as the HTTP-layer carrier for the core AppContext.
type RequestContext struct {
	requestID string
	appCtx    *application.AppContext
}

// NewRequestContext constructs the initial AppContext.
// It fails if the Domain validation for DeviceIdentity fails.
func NewRequestContext(id, ip, lang, uaRaw string, logger *slog.Logger) (*RequestContext, error) {
	ua := useragent.New(uaRaw)
	browser, _ := ua.Browser()

	// Building AppContext immediately enforces domain rules (e.g. required IP/UA)
	appCtx, err := application.NewAppContext(
		"", "", nil, // Unauthenticated initially
		uaRaw, ip, ua.OS(), browser, ua.Model(), lang, ua.Mobile(),
		logger.With(slog.String("req_id", id)),
	)
	if err != nil {
		return nil, err // Do not ignore: this is likely a validation error
	}

	return &RequestContext{
		requestID: id,
		appCtx:    appCtx,
	}, nil
}

// FromContext strictly extracts the RequestContext.
// It returns an error instead of a "Null Object" to force the caller to handle failures.
func FromContext(ctx context.Context) (*RequestContext, error) {
	rc, ok := ctx.Value(requestCtxKey).(*RequestContext)
	if !ok {
		return nil, ErrContextNotFound
	}
	if rc.appCtx == nil {
		return nil, ErrAppCtxNil
	}
	return rc, nil
}

// AttachUser performs a "mutation via replacement" to upgrade the AppContext with User info.
func (rc *RequestContext) AttachUser(userID, sessionID string, roles []string) error {
	identity := rc.appCtx.Client.Identity

	// Re-construct using the domain factory to ensure the UserID/SessionID are valid
	newAppCtx, err := application.NewAppContext(
		userID,
		sessionID,
		roles,
		identity.UserAgent(),
		identity.IPAddress(),
		identity.OS(),
		identity.Browser(),
		identity.Model(),
		identity.Language(),
		identity.IsMobile(),
		rc.appCtx.Logger,
	)
	if err != nil {
		return err
	}

	rc.appCtx = newAppCtx
	return nil
}

// AppContext returns the core context for domain layers.
func (rc *RequestContext) AppContext() *application.AppContext {
	return rc.appCtx
}

func (rc *RequestContext) Logger() *slog.Logger {
	return rc.appCtx.Logger
}

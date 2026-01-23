package middlewares

import (
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"
)

func JWTMiddleware(
	sessionTokenSvc aports.ISessionTokenIssuerService,
	deviceRepo dports.IDeviceRepository,
	idSvc dports.IIDService,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		// 1. Get base request context (Safe extraction)
		baseReq := utils.FromContext(c.Context())
		l := baseReq.Logger

		l.Debug("Authenticating request")

		// 2. Extract and Validate Header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return apperr.Unauthorized("authorization header is missing", nil)
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			return apperr.Validation("invalid authorization format", map[string]any{"scheme": "bearer"})
		}

		// 3. Validate Token
		claims, err := sessionTokenSvc.Validate(parts[1])
		if err != nil {
			return apperr.Unauthorized("invalid or expired token", err)
		}

		// 4. Device Integrity Checks
		if !idSvc.IsValid(claims.DeviceID) {
			return apperr.Validation("invalid device identifier", nil)
		}

		deviceIDVO, _ := valueobjects.NewDeviceID(claims.DeviceID)
		device, err := deviceRepo.GetByID(deviceIDVO)
		if err != nil || device == nil {
			return apperr.Unauthorized("session device not found", err)
		}

		if err := device.EnsureUsable(); err != nil {
			return apperr.Map(err)
		}

		// 5. Create AuthContext WITHOUT redundancy
		// Struct embedding allows us to just pass the whole RequestContext struct
		authCtx := &utils.AuthContext{
			RequestContext:           *baseReq,
			UserID:                   claims.UserID,
			Roles:                    claims.Roles,
			SessionRenewalRawTokenID: claims.SessionRenewalRawTokenID,
		}

		// 6. Enrich the Logger specifically for AuthContext
		authCtx.Logger = baseReq.Logger.With(
			slog.String("user_id", authCtx.UserID),
			slog.String("token_id", authCtx.SessionRenewalRawTokenID),
		)

		l.Debug("Authentication successful", slog.String("user_id", authCtx.UserID))

		// 7. Inject back into standard context
		c.SetContext(utils.WithAuth(c.Context(), authCtx))

		return c.Next()
	}
}

// package middlewares

// import (
// 	"go_auth/internal/adapters/http/fiber/utils"
// 	"go_auth/internal/core/application/apperr"
// 	"go_auth/internal/core/application/dto"
// 	aports "go_auth/internal/core/application/ports"
// 	dports "go_auth/internal/core/domain/ports"
// 	"go_auth/internal/core/domain/valueobjects"
// 	"log/slog"
// 	"strings"

// 	"github.com/gofiber/fiber/v3"
// )

// func JWTMiddleware(
// 	sessionTokenSvc aports.ISessionTokenIssuerService,
// 	deviceRepo dports.IDeviceRepository,
// 	idSvc dports.IIDService,
// ) fiber.Handler {
// 	return func(c fiber.Ctx) error {
// 		baseReq := utils.ReqCtx(c)
// 		l := baseReq.Logger

// 		l.Debug("Authenticating request")

// 		authHeader := c.Get("Authorization")
// 		if authHeader == "" {
// 			l.Warn("Authentication failed: missing authorization header")
// 			return apperr.Unauthorized("authorization header is missing", nil)
// 		}

// 		parts := strings.SplitN(authHeader, " ", 2)
// 		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
// 			l.Warn("Authentication failed: invalid authorization format")
// 			return apperr.Validation("invalid authorization format", map[string]any{"scheme": "bearer"})
// 		}

// 		claims, err := sessionTokenSvc.Validate(parts[1])
// 		if err != nil {
// 			l.Warn("Authentication failed: token validation error", slog.Any("error", err))
// 			return apperr.Unauthorized("invalid or expired token", err)
// 		}

// 		if !idSvc.IsValid(claims.DeviceID) {
// 			l.Warn("Authentication failed: malformed device id in claims", slog.String("device_id", claims.DeviceID))
// 			return apperr.Validation("invalid device identifier", nil)
// 		}

// 		deviceIDVO, err := valueobjects.NewDeviceID(claims.DeviceID)
// 		if err != nil {
// 			return apperr.Map(err)
// 		}
// 		device, err := deviceRepo.GetByID(deviceIDVO)
// 		if err != nil {
// 			l.Error("Database error during device lookup", slog.Any("error", err))
// 			return apperr.Map(err)
// 		}

// 		if device == nil {
// 			l.Warn("Authentication failed: session device not found", slog.String("device_id", claims.DeviceID))
// 			return apperr.Unauthorized("session device not found", nil)
// 		}

// 		if err := device.EnsureUsable(); err != nil {
// 			l.Warn("Authentication failed: device is restricted or inactive", slog.Any("error", err))
// 			return apperr.Map(err)
// 		}
// 		userID := claims.UserID
// 		tokenID := claims.SessionRenewalRawTokenID
// 		enrichedLogger := baseReq.Logger.With(
// 			slog.String("user_id", userID),
// 			slog.String("token_id", tokenID),
// 		)

// 		authCtx := &dto.AuthContext{
// 			RequestContext: &dto.RequestContext{
// 				RequestID:         baseReq.RequestID,
// 				DeviceFingerprint: baseReq.DeviceFingerprint,
// 				DeviceName:        baseReq.DeviceName,
// 				UserAgent:         baseReq.UserAgent,
// 				IPAddress:         baseReq.IPAddress,
// 				Logger:            enrichedLogger,
// 			},
// 			UserID:                userID,
// 			Roles:                 claims.Roles,
// 			SessionRenewalRawTokenID: tokenID,
// 		}

// 		l.Debug("Authentication successful",
// 			slog.String("user_id", userID),
// 			slog.Any("roles", claims.Roles),
// 		)

// 		c.SetContext(dto.Inject(c.Context(), authCtx))
// 		return c.Next()
// 	}
// }

package middlewares

import (
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func JWTMiddleware(
	tokenService aports.ITokenService,
	deviceRepo dports.IDeviceRepository,
	idSvc dports.IIDService,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		baseReq := utils.GetReqCtx(c)
		l := baseReq.Logger

		l.Debug("Authenticating request")

		authHeader := c.Get("Authorization")
		if authHeader == "" {
			l.Warn("Authentication failed: missing authorization header")
			return apperr.Unauthorized("authorization header is missing", nil)
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			l.Warn("Authentication failed: invalid authorization format")
			return apperr.Validation("invalid authorization format", map[string]any{"scheme": "bearer"})
		}

		claims, err := tokenService.ValidateAccessToken(parts[1])
		if err != nil {
			l.Warn("Authentication failed: token validation error", slog.Any("error", err))
			return apperr.Unauthorized("invalid or expired token", err)
		}

		if !idSvc.IsValid(claims.DeviceID) {
			l.Warn("Authentication failed: malformed device id in claims", slog.String("device_id", claims.DeviceID))
			return apperr.Validation("invalid device identifier", nil)
		}

		deviceID := valueobjects.ReconstituteDeviceID(claims.DeviceID)
		device, err := deviceRepo.GetByID(deviceID)
		if err != nil {
			l.Error("Database error during device lookup", slog.Any("error", err))
			return apperr.Map(err)
		}

		if device == nil {
			l.Warn("Authentication failed: session device not found", slog.String("device_id", claims.DeviceID))
			return apperr.Unauthorized("session device not found", nil)
		}

		if err := device.EnsureUsable(); err != nil {
			l.Warn("Authentication failed: device is restricted or inactive", slog.Any("error", err))
			return apperr.Map(err)
		}

		enrichedLogger := baseReq.Logger.With(
			slog.String("user_id", claims.Subject),
			slog.String("token_id", claims.JTI),
		)

		authCtx := &dto.AuthContext{
			RequestContext: &dto.RequestContext{
				RequestID:  baseReq.RequestID,
				DeviceID:   baseReq.DeviceID,
				DeviceName: baseReq.DeviceName,
				UserAgent:  baseReq.UserAgent,
				IPAddress:  baseReq.IPAddress,
				Logger:     enrichedLogger,
			},
			UserID:  claims.Subject,
			Roles:   claims.Roles,
			TokenID: claims.JTI,
		}

		l.Debug("Authentication successful",
			slog.String("user_id", claims.Subject),
			slog.Any("roles", claims.Roles),
		)

		c.SetUserContext(dto.Inject(c.UserContext(), authCtx))
		return c.Next()
	}
}

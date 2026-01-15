package middlewares

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func JWTMiddleware(
	tokenService aports.ITokenService,
	deviceRepo dports.IDeviceRepository,
	idSvc dports.IIDService,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Retrieve the Request Context (TraceID, IP, etc.)
		baseReq := utils.GetContext(c)
		traceID := baseReq.RequestID

		// 2. Transport Validation
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return apperr.Unauthorized("authorization header is missing", traceID, nil)
		}

		// 3. Protocol Validation (Bearer Scheme)
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return apperr.Validation("invalid authorization format", traceID, map[string]any{"scheme": "bearer"})
		}

		accessToken := parts[1]
		if accessToken == "" {
			return apperr.Unauthorized("access token is empty", traceID, nil)
		}

		// 4. Token Validation
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			// Maps expired or malformed JWT errors to apperr.TypeUnauthorized (401)
			return apperr.Unauthorized("invalid or expired token", traceID, err)
		}

		// 5. Device Binding & State Verification
		deviceIDStr := claims.DeviceID
		if !idSvc.IsValid(deviceIDStr) {
			return apperr.Validation("invalid device identifier in token", traceID, map[string]any{"device_id": deviceIDStr})
		}

		deviceID := valueobjects.ReconstituteDeviceID(deviceIDStr)
		device, err := deviceRepo.GetByID(deviceID)
		if err != nil {
			return apperr.Map(err, traceID)
		}

		if device == nil {
			return apperr.Unauthorized("session device not found", traceID, nil)
		}

		// Check domain invariants (e.g., Is the device revoked or inactive?)
		if err := device.EnsureUsable(); err != nil {
			// Maps derr.ErrDeviceRevoked etc. to 403 Forbidden or 401 Unauthorized via Map
			return apperr.Map(err, traceID)
		}

		// 6. Context Propagation: Upgrade to AuthContext
		authCtx := &dto.AuthContext{
			RequestContext: *baseReq,
			UserID:         claims.Subject,
			Roles:          claims.Roles,
			TokenID:        claims.JTI,
		}

		// Overwrite context with the hydrated AuthContext for downstream handlers
		c.Locals(dto.ContextKey, authCtx)

		return c.Next()
	}
}

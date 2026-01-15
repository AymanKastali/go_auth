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
		// 1. Get the existing Request Context (Pre-filled by your global middleware)
		// This ensures we keep the same RequestID, IP, and UserAgent
		baseReq := utils.GetContext(c)
		requestID := baseReq.RequestID

		// 2. Transport Validation
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return apperr.Invalid("authorization header is required", requestID, nil)
		}

		// 3. Protocol Validation
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return apperr.Invalid("invalid authorization format", requestID, nil)
		}

		accessToken := parts[1]
		if accessToken == "" {
			return apperr.Invalid("token cannot be empty", requestID, nil)
		}

		// 4. Security Service: Validate Token Identity
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			return apperr.FromDomain(err, requestID)
		}

		// 5. Domain Policy: Check Device/Session State
		deviceIDStr := claims.DeviceID
		if !idSvc.IsValid(deviceIDStr) {
			return apperr.Invalid("invalid device id format", requestID, nil)
		}
		if deviceIDStr != "" && deviceRepo != nil {
			deviceID := valueobjects.ReconstituteDeviceID(deviceIDStr)
			device, err := deviceRepo.GetByID(deviceID)
			if err != nil {
				return apperr.FromDomain(err, requestID)
			}

			if device == nil {
				return apperr.Unauthorized("session device not recognized", requestID, nil)
			}

			if err := device.EnsureUsable(); err != nil {
				return apperr.FromDomain(err, requestID)
			}
		}

		// 6. CONTEXT PROPAGATION: Upgrade to AuthContext
		// We embed the baseReq and add the security claims
		authCtx := &dto.AuthContext{
			RequestContext: *baseReq,
			UserID:         claims.Subject,
			Roles:          claims.Roles,
			TokenID:        claims.JTI,
		}

		// Overwrite the single context key with the full Auth DTO
		c.Locals(dto.ContextKey, authCtx)

		return c.Next()
	}
}

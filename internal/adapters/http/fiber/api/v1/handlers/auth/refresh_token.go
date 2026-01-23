package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	app_dto "go_auth/internal/core/application/dto" // Application layer DTOs
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

type RefreshTokenHandler struct {
	uc ports.ISessionRenewalUseCase
}

func NewRefreshTokenHandler(uc ports.ISessionRenewalUseCase) *RefreshTokenHandler {
	return &RefreshTokenHandler{uc: uc}
}

// Execute handles the session token rotation (refresh) process.
// @Summary      Refresh Tokens
// @Description  Rotates the session renewal token (refresh token) and issues a new access token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      dto.RefreshTokenRequest  true  "Refresh Token Details"
// @Success      200      {object}  dto.SuccessResponse{data=dto.LoginResponse} "Tokens rotated successfully"
// @Failure      400      {object}  dto.ErrorResponse "Bad Request - Invalid syntax or missing fields"
// @Failure      401      {object}  dto.ErrorResponse "Unauthorized - Invalid or expired refresh token"
// @Failure      403      {object}  dto.ErrorResponse "Forbidden - Device mismatch or security violation"
// @Failure      500      {object}  dto.ErrorResponse "Internal Server Error"
// @Router       /auth/refresh [post]
func (h *RefreshTokenHandler) Execute(c fiber.Ctx) error {
	// 1. Extract technical metadata and enriched logger
	reqCtx := utils.FromContext(c.Context())
	l := reqCtx.Logger

	var req dto.RefreshTokenRequest

	l.Info("Handling token refresh request")

	// 2. Bind JSON Body
	if err := c.Bind().Body(&req); err != nil {
		l.Warn("Failed to parse refresh token request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	// 3. Request Validation
	if err := utils.Validate(req); err != nil {
		l.Warn("refresh token request validation failed", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	// 4. Map to Application Input (The bridge)
	// We combine the RefreshToken from the body with the Fingerprint from the context
	input := app_dto.SessionRenewalInput{
		RefreshToken:      req.RefreshToken,
		DeviceFingerprint: reqCtx.DeviceFingerprint,
	}

	// 5. Execute Use Case with separated dependencies
	// No longer passing c.Context()
	authResp, err := h.uc.Execute(l, input)
	if err != nil {
		// Log specific failures inside the Use Case or via Global Error Handler
		return err
	}

	l.Info("Tokens rotated successfully")
	data := dto.LoginResponse{
		AccessToken:  authResp.SessionToken,
		RefreshToken: authResp.SessionRenewalToken,
	}
	resp := dto.SuccessResponse{Message: "tokens rotated successfully", Data: data}
	return c.Status(fiber.StatusOK).JSON(resp)
}

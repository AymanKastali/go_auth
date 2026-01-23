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

type LoginHandler struct {
	uc ports.ILoginUseCase
}

func NewLoginHandler(uc ports.ILoginUseCase) *LoginHandler {
	return &LoginHandler{uc: uc}
}

// Execute handles the user authentication process.
// @Summary      User Login
// @Description  Authenticates a user and returns access/refresh tokens. Uses device metadata for session management.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      dto.LoginRequest  true  "Login Credentials"
// @Success      200      {object}  dto.SuccessResponse{data=dto.LoginResponse} "Successfully authenticated"
// @Failure      400      {object}  dto.ErrorResponse "Bad Request - Invalid syntax"
// @Failure      401      {object}  dto.ErrorResponse "Unauthorized - Invalid credentials"
// @Failure      422      {object}  dto.ErrorResponse "Unprocessable Entity - Validation failed"
// @Failure      500      {object}  dto.ErrorResponse "Internal Server Error"
// @Router       /auth/login [post]
func (h *LoginHandler) Execute(c fiber.Ctx) error {
	// 1. Extract Enriched Logger and Metadata from the Adapter Context
	reqCtx := utils.FromContext(c.Context())
	l := reqCtx.Logger

	l.Info("Handling login request")

	// 2. Bind Request Body
	var req dto.LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		l.Warn("Failed to parse login request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	// 3. Request Validation
	if err := utils.Validate(req); err != nil {
		l.Warn("Login request validation failed",
			slog.String("email", req.Email),
			slog.Any("error", err),
		)
		return http.NewBadRequest(err)
	}

	// 4. Map to Application Input (Decoupling Transport from Business)
	input := app_dto.LoginInput{
		Email:             req.Email,
		Password:          req.Password,
		DeviceFingerprint: reqCtx.DeviceFingerprint,
		DeviceName:        utils.StringPtr(reqCtx.DeviceName),
		UserAgent:         utils.StringPtr(reqCtx.UserAgent),
		IPAddress:         utils.StringPtr(reqCtx.IPAddress),
	}

	// 5. Execute Use Case with separated Logger and Input
	authResp, err := h.uc.Execute(l, input)
	if err != nil {
		// Logic for logging the failure is already inside the UseCase or Error Handler
		return err
	}

	l.Info("User authenticated successfully", slog.String("email", req.Email))

	// 6. Return Success Envelope
	return utils.OK(c, dto.LoginResponse{
		AccessToken:  authResp.SessionToken,
		RefreshToken: authResp.SessionRenewalToken,
	}, "authenticated")
}

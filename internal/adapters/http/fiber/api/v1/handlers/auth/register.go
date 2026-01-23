package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

type RegisterHandler struct {
	uc ports.IRegisterUseCase
}

func NewRegisterHandler(
	uc ports.IRegisterUseCase,
) *RegisterHandler {
	return &RegisterHandler{uc: uc}
}

// Execute handles user registration requests.
// @Summary      Register User
// @Description  Creates a new user account with email and password.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      dto.RegisterRequest  true  "Registration Info"
// @Success      201      {object}  dto.SuccessResponse{data=dto.RegisteredUserResponse} "User successfully registered"
// @Failure      400      {object}  dto.ErrorResponse "Bad Request - Invalid syntax or missing fields"
// @Failure      409      {object}  dto.ErrorResponse "Conflict - Email already exists"
// @Failure      422      {object}  dto.ErrorResponse "Unprocessable Entity - Validation failed"
// @Failure      500      {object}  dto.ErrorResponse "Internal Server Error"
// @Router       /auth/register [post]
func (h *RegisterHandler) Execute(c fiber.Ctx) error {
	// 1. Extract Enriched Logger from Middleware Context
	reqCtx := utils.FromContext(c.Context())
	l := reqCtx.Logger

	var req dto.RegisterRequest

	l.Info("Handling registration request")

	// 2. Bind JSON Body
	if err := c.Bind().Body(&req); err != nil {
		l.Warn("Failed to parse registration request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	l.Debug("Validating registration data", slog.String("email", req.Email))

	// 3. Request Validation
	if err := utils.Validate(req); err != nil {
		l.Warn("Registration request validation failed",
			slog.String("email", req.Email),
			slog.Any("error", err),
		)
		return http.NewBadRequest(err)
	}

	// 4. Execute Use Case with separated technical and business dependencies
	// Note: We no longer pass c.Context()
	domainResp, err := h.uc.Execute(l, req.Email, req.Password)
	if err != nil {
		// Specific failure logging is handled inside the Use Case or Global Error Handler
		return err
	}

	l.Info("User registered successfully", slog.String("user_id", domainResp.UserID))

	// 5. Return Standardized Success Response
	return utils.Created(
		c,
		dto.RegisteredUserResponse{
			UserID: domainResp.UserID,
			Email:  domainResp.Email,
		},
		"user successfully registered",
	)
}

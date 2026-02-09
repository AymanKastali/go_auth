package fiberapp

import (
	"go_auth/internal/application"

	"github.com/gofiber/fiber/v3"
)

type PolicyHandler struct {
	publicPoliciesUC application.IGetPublicPoliciesUseCase
}

func NewPolicyHandler(publicPoliciesUC application.IGetPublicPoliciesUseCase) *PolicyHandler {
	return &PolicyHandler{publicPoliciesUC: publicPoliciesUC}
}

// @Summary  Get public policies
// @Description Returns password and registration policy rules (unauthenticated)
// @Tags     Policies
// @Produce  json
// @Success  200 {object} SuccessResponse{data=PolicyHTTPResponse}
// @Failure  500 {object} ErrorResponse
// @Router   /api/v1/policies [get]
func (h *PolicyHandler) GetPublicPolicies(c fiber.Ctx) error {
	resp, err := h.publicPoliciesUC.Execute(c.Context())
	if err != nil {
		return SendInternalError(c, "failed to retrieve policies")
	}

	return SendOK(c, "public policies", PolicyHTTPResponse{
		Password: PasswordPolicyHTTPResponse{
			MinLength:      resp.Password.MinLength,
			MaxLength:      resp.Password.MaxLength,
			RequireUpper:   resp.Password.RequireUpper,
			RequireNumber:  resp.Password.RequireNumber,
			RequireSpecial: resp.Password.RequireSpecial,
		},
		Registration: RegisterPolicyHTTPResponse{
			AllowPublic:    resp.Registration.AllowPublic,
			BlockedDomains: resp.Registration.BlockedDomains,
		},
	})
}

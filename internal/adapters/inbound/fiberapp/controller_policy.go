package fiberapp

import (
	"go_auth/internal/application/query"

	"github.com/gofiber/fiber/v3"
)

type PolicyController struct {
	publicPolicies query.IGetPublicPoliciesHandler
}

func NewPolicyController(publicPolicies query.IGetPublicPoliciesHandler) *PolicyController {
	return &PolicyController{publicPolicies: publicPolicies}
}

func (h *PolicyController) RegisterRoutes(api fiber.Router) {
	api.Get("/policies", h.GetPublicPolicies)
}

// @Summary  Get public policies
// @Description Returns password and registration policy rules (unauthenticated)
// @Tags     Policies
// @Produce  json
// @Success  200 {object} DataResponse{data=PolicyHTTPResponse}
// @Failure  500 {object} ErrorResponse
// @Router   /api/v1/policies [get]
func (h *PolicyController) GetPublicPolicies(c fiber.Ctx) error {
	resp, err := h.publicPolicies.Handle(c.Context())
	if err != nil {
		return SendInternalError(c, "failed to retrieve policies")
	}

	return SendOK(c, PolicyHTTPResponse{
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
		Activation: ActivationPolicyHTTPResponse{
			RequireEmail: resp.Activation.RequireEmail,
		},
	})
}

package query

import (
	"context"

	"go_auth/internal/domain"
)

type IGetPublicPoliciesHandler interface {
	Handle(ctx context.Context) (PublicPoliciesResponse, error)
}

type getPublicPoliciesHandler struct {
	passwordCfg  domain.PasswordPolicyConfig
	registerCfg  domain.RegisterPolicyConfig
	requireEmail bool
}

func NewGetPublicPoliciesHandler(
	passwordCfg domain.PasswordPolicyConfig,
	registerCfg domain.RegisterPolicyConfig,
	requireEmail bool,
) IGetPublicPoliciesHandler {
	return &getPublicPoliciesHandler{
		passwordCfg:  passwordCfg,
		registerCfg:  registerCfg,
		requireEmail: requireEmail,
	}
}

func (h *getPublicPoliciesHandler) Handle(_ context.Context) (PublicPoliciesResponse, error) {
	return PublicPoliciesResponse{
		Password: PasswordPolicyDTO{
			MinLength:      h.passwordCfg.MinLength,
			MaxLength:      h.passwordCfg.MaxLength,
			RequireUpper:   h.passwordCfg.RequireUpper,
			RequireNumber:  h.passwordCfg.RequireNumber,
			RequireSpecial: h.passwordCfg.RequireSpecial,
		},
		Registration: RegisterPolicyDTO{
			AllowPublic:    h.registerCfg.AllowPublic,
			BlockedDomains: h.registerCfg.BlockedDomains,
		},
		Activation: ActivationPolicyDTO{
			RequireEmail: h.requireEmail,
		},
	}, nil
}

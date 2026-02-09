package application

import (
	"context"

	"go_auth/internal/domain"
)

type getPublicPoliciesUseCase struct {
	passwordCfg   domain.PasswordPolicyConfig
	registerCfg   domain.RegisterPolicyConfig
	requireEmail  bool
}

func NewGetPublicPoliciesUseCase(
	passwordCfg domain.PasswordPolicyConfig,
	registerCfg domain.RegisterPolicyConfig,
	requireEmail bool,
) IGetPublicPoliciesUseCase {
	return &getPublicPoliciesUseCase{
		passwordCfg:  passwordCfg,
		registerCfg:  registerCfg,
		requireEmail: requireEmail,
	}
}

func (uc *getPublicPoliciesUseCase) Execute(_ context.Context) (PublicPoliciesResponse, error) {
	return PublicPoliciesResponse{
		Password: PasswordPolicyDTO{
			MinLength:      uc.passwordCfg.MinLength,
			MaxLength:      uc.passwordCfg.MaxLength,
			RequireUpper:   uc.passwordCfg.RequireUpper,
			RequireNumber:  uc.passwordCfg.RequireNumber,
			RequireSpecial: uc.passwordCfg.RequireSpecial,
		},
		Registration: RegisterPolicyDTO{
			AllowPublic:    uc.registerCfg.AllowPublic,
			BlockedDomains: uc.registerCfg.BlockedDomains,
		},
		Activation: ActivationPolicyDTO{
			RequireEmail: uc.requireEmail,
		},
	}, nil
}

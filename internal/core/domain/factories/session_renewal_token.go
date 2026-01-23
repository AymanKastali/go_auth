package factories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/policies"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type sessionRenewalTokenFactory struct {
	idSvc  ports.IIDService
	policy policies.SessionRenewalTokenPolicy
}

func NewSessionRenewalTokenFactory(
	idSvc ports.IIDService,
	policy policies.SessionRenewalTokenPolicy,
) *sessionRenewalTokenFactory {
	return &sessionRenewalTokenFactory{
		idSvc:  idSvc,
		policy: policy,
	}
}

func (f *sessionRenewalTokenFactory) New(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	hashed valueobjects.SessionRenewalHashedToken,
	now valueobjects.Timepoint,
) (*entities.SessionRenewalToken, error) {

	tokenID, err := valueobjects.NewSessionRenewalRawTokenID(f.idSvc.Generate())
	if err != nil {
		return nil, err
	}

	expiresAt := now.Add(f.policy.Lifetime)

	return entities.NewSessionRenewalToken(
		tokenID,
		userID,
		deviceID,
		hashed,
		expiresAt,
		now,
	)
}

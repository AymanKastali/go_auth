package outbound

import (
	"go_auth/internal/domain"

	"github.com/oklog/ulid/v2"
)

// ID Service
type ulidIDGenerator struct{}

func NewULIDIdGenerator() domain.IIDGenerator {
	return &ulidIDGenerator{}
}

func (g *ulidIDGenerator) GenerateUserID() (domain.UserID, error) {
	id := ulid.Make()
	uidVO, err := domain.NewUserID(id.String())
	if err != nil {
		return domain.ZeroUserID, err
	}
	return uidVO, nil
}

func (g *ulidIDGenerator) GenerateSessionID() (domain.SessionID, error) {
	id := ulid.Make()
	sidVO, err := domain.NewSessionID(id.String())
	if err != nil {
		return domain.ZeroSessionID, err
	}
	return sidVO, nil
}

func (g *ulidIDGenerator) GenerateRecoveryTokenID() (domain.RecoveryTokenID, error) {
	id := ulid.Make()
	tidVO, err := domain.NewRecoveryTokenID(id.String())
	if err != nil {
		return domain.ZeroRecoveryTokenID, err
	}
	return tidVO, nil
}

func (g *ulidIDGenerator) GenerateActivationTokenID() (domain.ActivationTokenID, error) {
	id := ulid.Make()
	tidVO, err := domain.NewActivationTokenID(id.String())
	if err != nil {
		return domain.ZeroActivationTokenID, err
	}
	return tidVO, nil
}

func (g *ulidIDGenerator) GenerateRoleID() (domain.RoleID, error) {
	id := ulid.Make()
	roleID, err := domain.NewRoleID(id.String())
	if err != nil {
		return domain.ZeroRoleID, err
	}
	return roleID, nil
}

// ULIDGenerator for standalone ULID generation (e.g. request IDs)
type ULIDGenerator struct{}

func NewULIDGenerator() *ULIDGenerator {
	return &ULIDGenerator{}
}

func (g *ULIDGenerator) Generate() (string, error) {
	id := ulid.Make()
	return id.String(), nil
}

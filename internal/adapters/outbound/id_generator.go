package outbound

import (
	"go_auth/internal/domain"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
)

// ID Service
type uuidV7Generator struct{}

func NewUUIDV7Generator() domain.IIDGenerator {
	return &uuidV7Generator{}
}

func (g *uuidV7Generator) GenerateUserID() (domain.UserID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.ZeroUserID, domain.ErrInternal
	}
	uidVO, err := domain.NewUserID(id.String())
	if err != nil {
		return domain.ZeroUserID, err
	}
	return uidVO, nil
}

func (g *uuidV7Generator) GenerateSessionID() (domain.SessionID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.ZeroSessionID, domain.ErrInternal
	}
	uidVO, err := domain.NewSessionID(id.String())
	if err != nil {
		return domain.ZeroSessionID, err
	}
	return uidVO, nil
}

func (g *uuidV7Generator) GenerateRecoveryTokenID() (domain.RecoveryTokenID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.ZeroRecoveryTokenID, domain.ErrInternal
	}
	uidVO, err := domain.NewRecoveryTokenID(id.String())
	if err != nil {
		return domain.ZeroRecoveryTokenID, err
	}
	return uidVO, nil
}

func (g *uuidV7Generator) GenerateActivationTokenID() (domain.ActivationTokenID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.ZeroActivationTokenID, domain.ErrInternal
	}
	uidVO, err := domain.NewActivationTokenID(id.String())
	if err != nil {
		return domain.ZeroActivationTokenID, err
	}
	return uidVO, nil
}

func (g *uuidV7Generator) GenerateRoleID() (domain.RoleID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.ZeroRoleID, domain.ErrInternal
	}
	roleID, err := domain.NewRoleID(id.String())
	if err != nil {
		return domain.ZeroRoleID, err
	}
	return roleID, nil
}

// ULID Generator
type ULIDGenerator struct{}

func NewULIDGenerator() *ULIDGenerator {
	return &ULIDGenerator{}
}

func (g *ULIDGenerator) Generate() (string, error) {
	id := ulid.Make()
	return id.String(), nil
}

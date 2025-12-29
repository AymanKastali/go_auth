package factories

import (
	"go_auth/internal/domain/domainerr"
	"go_auth/internal/domain/entities"
	"go_auth/internal/domain/valueobjects"
)

const op = "UserFactory.New"

type UserFactory struct{}

func (f *UserFactory) New(
	id valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.PasswordHash,
	status valueobjects.UserStatus,
	roles []valueobjects.Role,
) (*entities.User, error) {

	if id.IsZero() {
		return nil, domainerr.NewDomainRequiredAttrError("user id", op)
	}
	if email.Value == "" {
		return nil, domainerr.NewDomainRequiredAttrError("email", op)
	}
	if passwordHash.Value == "" {
		return nil, domainerr.NewDomainRequiredAttrError("password", op)
	}
	if status == "" {
		return nil, domainerr.NewDomainRequiredAttrError("status", op)
	}
	if roles == nil {
		roles = []valueobjects.Role{}
	}

	return &entities.User{
		ID:           id,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       status,
		Roles:        roles,
	}, nil
}

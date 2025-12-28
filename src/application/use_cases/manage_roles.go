package use_cases

import (
	"errors"
	"go_auth/src/adapters/mappers"
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/use_cases"
	"go_auth/src/domain/ports/repositories"
	"go_auth/src/domain/value_objects"
	"strings"
)

type manageRoleUseCase struct {
	userRepo   repositories.UserRepositoryPort
	uuidMapper *mappers.UUIDMapper
}

var _ use_cases.ManageRoleUseCasePort = (*manageRoleUseCase)(nil)

func NewManageRoleUseCase(
	userRepository repositories.UserRepositoryPort,
	uuidMapper *mappers.UUIDMapper,
) *manageRoleUseCase {
	return &manageRoleUseCase{
		userRepo:   userRepository,
		uuidMapper: uuidMapper,
	}
}

func (uc *manageRoleUseCase) UpdateRole(req dto.ManageRoleInput) error {
	userIDVO, err := uc.uuidMapper.UserIdFromString(req.UserID)
	if err != nil {
		return err
	}
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	role := value_objects.Role(strings.ToUpper(req.Role))

	if req.Action == "grant" {
		user.AddRole(role)
	} else {
		user.RemoveRole(role)
	}

	return uc.userRepo.Update(user)
}

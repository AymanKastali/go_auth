package use_cases

import (
	"go_auth/src/application/dto"
)

type ManageRoleUseCasePort interface {
	UpdateRole(req dto.ManageRoleInput) error
}

package use_cases

import (
	"go_auth/internal/application/dto"
)

type ManageRoleUseCasePort interface {
	UpdateRole(req dto.ManageRoleInput) error
}

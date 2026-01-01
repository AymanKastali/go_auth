package use_cases

import (
	"go_auth/internal/core/application/dto"
)

type ManageRoleUseCasePort interface {
	UpdateRole(req dto.ManageRoleInput) error
}

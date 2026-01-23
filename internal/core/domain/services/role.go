package services

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"strings"
)

type roleService struct {
	roleRepo ports.IRoleRepository
	idSvc    ports.IIDService
}

func NewRoleService(roleRepo ports.IRoleRepository, idSvc ports.IIDService) *roleService {
	return &roleService{
		roleRepo: roleRepo,
		idSvc:    idSvc,
	}
}

// EnsureRoleExists is idempotent: it returns the role if it exists, or creates it if not.
// Perfect for seeders.
func (s *roleService) EnsureRoleExists(name string, now valueobjects.Timepoint) (*aggregates.Role, error) {
	name = strings.ToLower(strings.TrimSpace(name))

	existing, err := s.roleRepo.GetByName(name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	// If it doesn't exist, use the internal creation logic
	return s.createNew(name, now)
}

// CreateNewRole is explicit: it returns an error if the role already exists.
// Perfect for Admin Dashboards.
func (s *roleService) CreateNewRole(name string, now valueobjects.Timepoint) (*aggregates.Role, error) {
	name = strings.ToLower(strings.TrimSpace(name))

	existing, err := s.roleRepo.GetByName(name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, derr.NewErrRoleAlreadyExists(name)
	}

	return s.createNew(name, now)
}

// createNew is a private helper to keep things DRY
func (s *roleService) createNew(name string, now valueobjects.Timepoint) (*aggregates.Role, error) {
	roleID, err := valueobjects.NewRoleID(s.idSvc.Generate())
	if err != nil {
		return nil, err
	}

	return aggregates.NewRole(roleID, name, now)
}

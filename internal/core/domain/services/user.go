package services

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"strings"
)

type userService struct {
	userRepo    ports.IUserRepository
	roleRepo    ports.IRoleRepository
	pwdHasher   ports.IPasswordHasherService
	userFactory ports.IUserFactory
	pwdPolicy   ports.IPasswordPolicyService
}

func NewUserService(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	pwdHasher ports.IPasswordHasherService,
	userFactory ports.IUserFactory,
	pwdPolicy ports.IPasswordPolicyService,
) *userService {
	return &userService{
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		pwdHasher:   pwdHasher,
		userFactory: userFactory,
		pwdPolicy:   pwdPolicy,
	}
}

func (s *userService) RegisterUser(
	email valueobjects.Email,
	rawPwd valueobjects.RawPassword,
	now valueobjects.Timepoint,
) (*aggregates.User, error) {
	// 1. Password Policy Check (Fail Fast)
	// We do this before hitting the DB or hashing (saves CPU/IO)
	if err := s.pwdPolicy.Validate(rawPwd); err != nil {
		return nil, err
	}

	// 2. Business Rule: Uniqueness (IO Check)
	exists, err := s.userRepo.ExistsByEmail(email)
	if err != nil {
		return nil, err // DB errors bubble up to be mapped to 500
	}
	if exists {
		return nil, derr.NewErrEmailAlreadyUsed(email.String())
	}

	// 3. Business Rule: Default Roles
	role, err := s.roleRepo.GetByName("user")
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, derr.NewErrDefaultRoleMissing("user")
	}

	// 4. Security: Hashing (Expensive Operation)
	hashedPwd, err := s.pwdHasher.Hash(rawPwd)
	if err != nil {
		return nil, err
	}

	// 5. Delegation: Factory handles Identity and Assembly
	// Factory is "pure": No IO, just building the object
	user, err := s.userFactory.New(email, hashedPwd, []valueobjects.RoleID{role.ID()}, now)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) AssignRole(user *aggregates.User, roleName string, now valueobjects.Timepoint) error {
	name := strings.ToUpper(strings.TrimSpace(roleName))

	role, err := s.roleRepo.GetByName(name)
	if err != nil {
		return err
	}
	if role == nil {
		return derr.NewErrRoleNotFound(name)
	}

	// Aggregate handles business rules (e.g., "User must be active")
	return user.AddRoleID(role.ID(), now)
}

func (s *userService) RemoveRole(
	user *aggregates.User,
	roleName string,
	now valueobjects.Timepoint,
) error {
	// 1. Normalization
	name := strings.ToUpper(strings.TrimSpace(roleName))

	// 2. Lookup the Role ID
	role, err := s.roleRepo.GetByName(name)
	if err != nil {
		return err
	}
	if role == nil {
		return derr.NewErrRoleNotFound(name)
	}

	// 3. Delegate to Aggregate
	// The User aggregate's RemoveRoleID method already handles the
	// business rule: "Cannot remove the last role"
	return user.RemoveRoleID(role.ID(), now)
}

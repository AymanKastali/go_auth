package services

import (
	"fmt"
	"go_auth/src/adapters/config"
	"go_auth/src/application/ports/security"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	"go_auth/src/domain/value_objects"
)

type SeedAdminService struct {
	userRepo       repositories.UserRepositoryPort
	passwordHasher security.HashPasswordPort
	pwHashFactory  factories.PasswordHashFactory
	userFactory    factories.UserFactory
	idFactory      factories.IDFactory
	cfg            *config.SeederConfig
}

func NewSeedAdminService(
	repo repositories.UserRepositoryPort,
	passwordHasher security.HashPasswordPort,
	pwHashFactory factories.PasswordHashFactory,
	userFactory factories.UserFactory,
	idFactory factories.IDFactory,
	seederConfig *config.SeederConfig,
) *SeedAdminService {
	return &SeedAdminService{
		userRepo:       repo,
		passwordHasher: passwordHasher,
		pwHashFactory:  pwHashFactory,
		userFactory:    userFactory,
		idFactory:      idFactory,
		cfg:            seederConfig,
	}
}

func (s *SeedAdminService) SeedAdmin() error {
	adminEmail := s.cfg.AdminEmail
	adminPass := s.cfg.AdminPassword

	// Validation: Ensure env variables aren't empty
	if adminEmail == "" || adminPass == "" {
		return fmt.Errorf("seeder: ADMIN_EMAIL or ADMIN_PASSWORD environment variables are not set")
	}

	// 1. Check if admin already exists
	emailVO := value_objects.Email{Value: adminEmail}
	exists, err := s.userRepo.GetByEmail(emailVO)
	if err == nil && exists != nil {
		return nil // Admin already seeded, exit cleanly
	}

	// 2. Hash the password from .env
	hash, err := s.passwordHasher.Hash(adminPass)
	if err != nil {
		return fmt.Errorf("seeder: failed to hash admin password: %w", err)
	}
	pw := s.pwHashFactory.New(hash)

	// 3. Create the Admin Entity via Factory
	admin, err := s.userFactory.New(
		s.idFactory.NewUserID(),
		emailVO,
		pw,
		value_objects.UserActive,
		[]value_objects.Role{value_objects.RoleAdmin}, // FIX: Use RoleAdmin, not RoleUser
	)

	if err != nil {
		return fmt.Errorf("seeder: failed to create admin entity: %w", err)
	}

	// 4. Save to Repository
	// FIX: Removed the duplicate Save call.
	if err := s.userRepo.Save(admin); err != nil {
		return fmt.Errorf("seeder: failed to save admin to repository: %w", err)
	}

	return nil
}

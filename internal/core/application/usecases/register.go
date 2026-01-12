package usecases

import (
	"errors"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type registerUseCase struct {
	userRepo       dports.UserRepositoryPort
	roleRepo       dports.RoleRepositoryPort
	passwordHasher aports.HashPasswordServicePort
	uuidGenerator  interfaces.IUUIDGeneratorService
	clock          interfaces.IClock
	logger         *slog.Logger
}

var _ aports.RegisterUseCasePort = (*registerUseCase)(nil)

func NewRegisterUseCase(
	userRepo dports.UserRepositoryPort,
	roleRepo dports.RoleRepositoryPort,
	passwordHasher aports.HashPasswordServicePort,
	uuidGenerator interfaces.IUUIDGeneratorService,
	clock interfaces.IClock,
	logger *slog.Logger,
) aports.RegisterUseCasePort {
	return &registerUseCase{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		uuidGenerator:  uuidGenerator,
		clock:          clock,
		logger:         logger,
	}
}

func (uc *registerUseCase) Execute(email, password string) (*dto.RegisteredUserDTO, error) {
	// 1. Value Object Creation (Validation Intent)
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.Validation(err)
	}

	existingUser, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		// This is a technical error (DB down, etc.)
		return nil, apperr.Internal(err)
	}
	if existingUser != nil {
		// The user exists, return a Conflict error
		return nil, apperr.Conflict(errors.New("user already exists with this email"))
	}

	// 2. Hash Password (Infrastructure Intent)
	hash, err := uc.passwordHasher.Hash(password)
	if err != nil {
		uc.logger.Error("Password hashing failed", "error", err)
		return nil, apperr.Internal(err)
	}

	pw, err := valueobjects.NewHashedPassword(hash)
	if err != nil {
		return nil, apperr.Validation(err)
	}

	// 3. Dependency Fetching (Internal Intent - Misconfiguration)
	userRole, err := uc.roleRepo.GetByName("user")
	if err != nil {
		return nil, apperr.Internal(err)
	}
	if userRole == nil {
		uc.logger.Error("System misconfiguration: user role missing")
		return nil, apperr.Internal(errors.New("required system role 'user' is missing"))
	}

	userID, err := uc.uuidGenerator.NewUserID()
	if err != nil {
		uc.logger.Error("Failed to generate user ID", "error", err)
		return nil, apperr.Internal(err)
	}

	// 4. Aggregate Root Instantiation (Validation/Logic Intent)
	user, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{userRole.ID()},
		uc.clock.NowUTC(),
	)
	if err != nil {
		// If NewUser fails, it means domain invariants weren't met
		return nil, apperr.Validation(err)
	}

	// 5. Persistence (Internal/Conflict Intent)
	if err := uc.userRepo.Save(user); err != nil {
		// Note: If your Repo detects a duplicate email,
		// it should return a derr.OpRule conflict, which Conflict(err) will wrap.
		return nil, apperr.Conflict(err)
	}

	return &dto.RegisteredUserDTO{
		UserID: user.ID().Value(),
		Email:  user.Email().Value(),
	}, nil
}

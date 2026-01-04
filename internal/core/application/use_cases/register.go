package use_cases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type registerUseCase struct {
	userRepository repositories.UserRepositoryPort
	roleRepository repositories.RoleRepositoryPort
	passwordHasher security.HashPasswordPort
	logger         *slog.Logger
}

var _ use_cases.RegisterUseCasePort = (*registerUseCase)(nil)

// Constructor
func NewRegisterUseCase(
	userRepo repositories.UserRepositoryPort,
	roleRepo repositories.RoleRepositoryPort,
	passwordHasher security.HashPasswordPort,
	logger *slog.Logger,
) *registerUseCase {
	return &registerUseCase{
		userRepository: userRepo,
		roleRepository: roleRepo,
		passwordHasher: passwordHasher,
		logger:         logger,
	}
}

// Register creates a new user with the default USER role
func (h *registerUseCase) Register(email string, password string) (*dto.RegisteredUserDTO, error) {
	// 1️⃣ DOMAIN: Validate email
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 2️⃣ INFRA: Check if user exists
	existing, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.NewInternalErr("database query failed")
	}
	if existing != nil {
		return nil, apperr.NewConflictErr("User", "email is already registered")
	}

	// 3️⃣ INFRA: Hash password
	hash, err := h.passwordHasher.Hash(password)
	if err != nil {
		return nil, apperr.NewInternalErr("password encryption failed")
	}
	pw := valueobjects.NewHashedPassword(hash)

	// 4️⃣ DOMAIN: Fetch default USER role
	userRole, err := h.roleRepository.GetByName("USER")
	if err != nil {
		h.logger.Error("Failed to fetch USER role", "error", err)
		return nil, apperr.NewInternalErr("failed to assign default role")
	}
	if userRole == nil {
		h.logger.Error("USER role does not exist")
		return nil, apperr.NewInternalErr("USER role missing")
	}

	// 5️⃣ DOMAIN: Create user entity
	user, err := entities.NewUser(
		valueobjects.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{userRole.ID()},
		time.Now().UTC(),
	)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 6️⃣ INFRA: Save user
	if err := h.userRepository.Save(user); err != nil {
		return nil, apperr.NewInternalErr("user creation failed")
	}

	// 7️⃣ RETURN DTO
	return &dto.RegisteredUserDTO{
		UserID: user.ID().String(),
		Email:  user.Email().Value(),
	}, nil
}

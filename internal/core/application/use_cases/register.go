package use_cases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type registerUseCase struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher security.HashPasswordPort
	logger         *slog.Logger
}

var _ use_cases.RegisterUseCasePort = (*registerUseCase)(nil)

func NewRegisterUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher security.HashPasswordPort,
	logger *slog.Logger,
) *registerUseCase {
	return &registerUseCase{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		logger:         logger,
	}
}

func (h *registerUseCase) Register(email string, password string) (*dto.RegisteredUserDTO, error) {
	// 1. DOMAIN: Validation
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 2. INFRASTRUCTURE & APPLICATION: Check existence
	existing, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.NewInternal("database query failed")
	}
	if existing != nil {
		// APPLICATION CONCERN: Conflict
		return nil, apperr.NewConflict("email is already registered")
	}

	// 3. INFRASTRUCTURE: Hashing
	hash, err := h.passwordHasher.Hash(password)
	if err != nil {
		return nil, apperr.NewInternal("password encryption failed")
	}
	pw := valueobjects.NewHashedPassword(hash)

	// 4. DOMAIN: Create entity
	user, err := entities.NewUser(
		valueobjects.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.Role{valueobjects.RoleUser},
		time.Now().UTC(),
	)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 5. INFRASTRUCTURE: Save
	if err := h.userRepository.Save(user); err != nil {
		return nil, apperr.NewInternal("user creation failed")
	}

	return &dto.RegisteredUserDTO{
		UserID: user.ID().String(),
		Email:  user.Email().Value(),
	}, nil
}

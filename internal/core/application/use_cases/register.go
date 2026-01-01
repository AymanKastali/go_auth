package use_cases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/events"
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
	h.logger.Info("Starting user registration", "email", email)

	// 1. Validate email
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		h.logger.Error("Invalid email provided", "email", email, "error", err)
		return nil, apperr.FromDomainError(err)
	}

	// 2. Check if user already exists
	existing, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		h.logger.Error("Failed to check existing user", "email", email, "error", err)
		return nil, apperr.FromDomainError(err)
	}
	if existing != nil {
		h.logger.Warn("Email already registered", "email", email)
		return nil, apperr.FromDomainError(err)
	}

	// 3. Hash password
	hash, err := h.passwordHasher.Hash(password)
	if err != nil {
		h.logger.Error("Failed to hash password", "email", email, "error", err)
		return nil, apperr.FromDomainError(err)
	}
	pw := valueobjects.NewHashedPassword(hash)

	// 4. Create user entity
	user, err := entities.NewUser(
		valueobjects.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.Role{valueobjects.RoleUser},
		time.Now().UTC(),
	)
	if err != nil {
		h.logger.Error("Failed to create user entity", "email", email, "error", err)
		return nil, apperr.FromDomainError(err)
	}

	// 5. Save user
	if err := h.userRepository.Save(user); err != nil {
		h.logger.Error("Failed to save user", "email", email, "error", err)
		return nil, apperr.FromDomainError(err)
	}

	// 6. Publish event
	userIDVO := user.ID()
	h.logger.Info("User registered successfully", "email", email, "userID", userIDVO)
	_ = events.UserRegistered{UserID: userIDVO} // implement actual event publishing

	// 7. Return response DTO
	return &dto.RegisteredUserDTO{
		UserID: user.ID().String(),
		Email:  user.Email().Value(),
	}, nil
}

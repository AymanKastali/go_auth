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

	// 1. DOMAIN: Validate email (Business Rule)
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		h.logger.Error("Invalid email provided", "email", email, "error", err)
		return nil, apperr.MapDomain(err) // Preserves the Attr() for the API
	}

	// 2. INFRASTRUCTURE: Check if user already exists
	existing, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		h.logger.Error("Failed to check existing user", "email", email, "error", err)
		return nil, apperr.ErrInternal // Securely hide DB specifics
	}
	if existing != nil {
		h.logger.Warn("Email already registered", "email", email)
		// This is a process conflict, return the specific app error
		return nil, apperr.ErrConflict
	}

	// 3. INFRASTRUCTURE: Hash password
	hash, err := h.passwordHasher.Hash(password)
	if err != nil {
		h.logger.Error("Failed to hash password", "error", err)
		return nil, apperr.ErrInternal
	}
	pw := valueobjects.NewHashedPassword(hash)

	// 4. DOMAIN: Create user entity
	// Note: We use the Domain constants for default state and roles
	user, err := entities.NewUser(
		valueobjects.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.Role{valueobjects.RoleUser},
		time.Now().UTC(),
	)
	if err != nil {
		h.logger.Error("Entity validation failed", "error", err)
		return nil, apperr.MapDomain(err)
	}

	// 5. INFRASTRUCTURE: Save user
	if err := h.userRepository.Save(user); err != nil {
		h.logger.Error("Failed to save user repository", "error", err)
		return nil, apperr.ErrInternal
	}

	// 6. LOGGING & EVENTS
	h.logger.Info("User registered successfully", "userID", user.ID())
	// Note: In a production app, event publishing would be handled here
	_ = events.UserRegistered{UserID: user.ID()}

	// 7. RETURN DTO
	return &dto.RegisteredUserDTO{
		UserID: user.ID().String(),
		Email:  user.Email().Value(),
	}, nil
}

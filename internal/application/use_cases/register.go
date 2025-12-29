package use_cases

import (
	"go_auth/internal/application/apperr"
	"go_auth/internal/application/dto"
	"go_auth/internal/application/ports/security"
	"go_auth/internal/application/ports/use_cases"
	"go_auth/internal/domain/events"
	"go_auth/internal/domain/factories"
	"go_auth/internal/domain/ports/repositories"
	"go_auth/internal/domain/valueobjects"
	"log/slog"
)

type registerUseCase struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher security.HashPasswordPort
	idFactory      factories.IDFactory
	emailFactory   factories.EmailFactory
	pwdHashFactory factories.PasswordHashFactory
	userFactory    factories.UserFactory
	logger         *slog.Logger
}

var _ use_cases.RegisterUseCasePort = (*registerUseCase)(nil)

func NewRegisterUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher security.HashPasswordPort,
	idFactory factories.IDFactory,
	emailFactory factories.EmailFactory,
	pwHashFactory factories.PasswordHashFactory,
	userFactory factories.UserFactory,
	logger *slog.Logger,
) *registerUseCase {
	return &registerUseCase{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		idFactory:      idFactory,
		emailFactory:   emailFactory,
		pwdHashFactory: pwHashFactory,
		userFactory:    userFactory,
		logger:         logger,
	}
}

func (h *registerUseCase) Register(email string, password string) (*dto.RegisteredUserDTO, error) {
	h.logger.Info("Starting user registration", "email", email)

	// 1. Validate email
	emailVO, err := h.emailFactory.New(email)
	if err != nil {
		h.logger.Error("Invalid email provided", "email", email, "error", err)
		return nil, apperr.ErrInvalidEmail
	}

	// 2. Check if user already exists
	existing, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		h.logger.Error("Failed to check existing user", "email", email, "error", err)
		return nil, apperr.ErrInternal
	}
	if existing != nil {
		h.logger.Warn("Email already registered", "email", email)
		return nil, apperr.ErrEmailAlreadyRegistered
	}

	// 3. Hash password
	hash, err := h.passwordHasher.Hash(password)
	if err != nil {
		h.logger.Error("Failed to hash password", "email", email, "error", err)
		return nil, apperr.ErrInternal
	}
	pw := h.pwdHashFactory.New(hash)

	// 4. Create user entity
	user, err := h.userFactory.New(
		h.idFactory.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.Role{valueobjects.RoleUser},
	)
	if err != nil {
		h.logger.Error("Failed to create user entity", "email", email, "error", err)
		return nil, apperr.ErrInternal
	}

	// 5. Save user
	if err := h.userRepository.Save(user); err != nil {
		h.logger.Error("Failed to save user", "email", email, "error", err)
		return nil, apperr.ErrInternal
	}

	// 6. Publish event
	h.logger.Info("User registered successfully", "email", email, "userID", user.ID)
	_ = events.UserRegistered{UserID: user.ID} // implement actual event publishing

	// 7. Return response DTO
	return &dto.RegisteredUserDTO{
		UserID: user.ID.Value.String(),
		Email:  user.Email.Value,
	}, nil
}

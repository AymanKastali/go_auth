package use_cases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type RegisterUseCase struct {
	userRepository repositories.UserRepositoryPort
	roleRepository repositories.RoleRepositoryPort
	passwordHasher security.HashPasswordPort
	logger         *slog.Logger
}

func NewRegisterUseCase(
	userRepo repositories.UserRepositoryPort,
	roleRepo repositories.RoleRepositoryPort,
	passwordHasher security.HashPasswordPort,
	logger *slog.Logger,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepository: userRepo,
		roleRepository: roleRepo,
		passwordHasher: passwordHasher,
		logger:         logger,
	}
}

// Register creates a new user with the default user role
func (h *RegisterUseCase) Register(email string, password string) (*dto.RegisteredUserDTO, error) {
	// 1️⃣ DOMAIN: Validate email
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 2️⃣ INFRA: Hash password
	// We do this before checking roles to fail early if hashing infrastructure is down
	hash, err := h.passwordHasher.Hash(password)
	if err != nil {
		h.logger.Error("Password hashing failed", "error", err)
		return nil, apperr.NewInternalErr("security component failure")
	}
	pw := valueobjects.NewHashedPassword(hash)

	// 3️⃣ INFRA: Fetch default user role
	// Your roleRepo now returns apperr, so we return err directly
	userRole, err := h.roleRepository.GetByName("user")
	if err != nil {
		return nil, err
	}
	if userRole == nil {
		h.logger.Error("System misconfiguration: user role missing")
		return nil, apperr.NewInternalErr("default role assignment failed")
	}

	// 4️⃣ DOMAIN: Create user entity
	user, err := aggregates.NewUser(
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

	// 5️⃣ INFRA: Save user
	// Note: If the email already exists, userRepository.Save returns apperr.AlreadyExistsErr
	// because it uses r.handleError(err, u.Email().String()) internally.
	if err := h.userRepository.Save(user); err != nil {
		return nil, err
	}

	// 6️⃣ RETURN DTO
	return &dto.RegisteredUserDTO{
		UserID: user.ID().String(),
		Email:  user.Email().Value(),
	}, nil
}

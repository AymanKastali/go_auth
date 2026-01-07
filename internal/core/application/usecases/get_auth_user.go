package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type authUserUseCase struct {
	userRepo ports.UserRepositoryPort
	roleRepo ports.RoleRepositoryPort
	logger   *slog.Logger
}

var _ ports.AuthUserUseCasePort = (*authUserUseCase)(nil)

func NewAuthUserUseCase(
	userRepo ports.UserRepositoryPort,
	roleRepo ports.RoleRepositoryPort,
	logger *slog.Logger,
) ports.AuthUserUseCasePort {
	return &authUserUseCase{
		userRepo: userRepo,
		roleRepo: roleRepo,
		logger:   logger,
	}
}

func (h *authUserUseCase) Execute(userID string) (*dto.AuthUser, error) {
	// 1️⃣ Parse user ID
	userIDVO, err := valueobjects.UserIDFromString(userID)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 2️⃣ Fetch user entity
	user, err := h.userRepo.GetByID(userIDVO)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, apperr.NewNotFoundErr("user", userID)
	}

	// 3️⃣ Map role IDs -> role names
	roleIDs := user.RoleIDs()
	roles := make([]string, len(roleIDs))
	for i, rID := range roleIDs {
		role, err := h.roleRepo.GetByID(rID)
		if err != nil {
			h.logger.Error("Failed to fetch role", "roleID", rID, "error", err)
			return nil, apperr.NewInternalErr("failed to fetch user roles")
		}
		if role == nil {
			h.logger.Warn("Role not found for user", "roleID", rID)
			roles[i] = "UNKNOWN"
			continue
		}
		roles[i] = role.Name()
	}

	// 4️⃣ Return DTO
	return &dto.AuthUser{
		ID:        user.ID().String(),
		Email:     user.Email().String(),
		Status:    string(user.Status()),
		Roles:     roles,
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}, nil
}

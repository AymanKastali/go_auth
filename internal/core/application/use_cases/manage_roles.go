package use_cases

import (
	"errors"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"strings"
)

type manageRoleUseCase struct {
	userRepo repositories.UserRepositoryPort
	roleRepo repositories.RoleRepositoryPort
	logger   *slog.Logger
}

var _ use_cases.ManageRoleUseCasePort = (*manageRoleUseCase)(nil)

func NewManageRoleUseCase(
	userRepository repositories.UserRepositoryPort,
	roleRepository repositories.RoleRepositoryPort,
	logger *slog.Logger,
) *manageRoleUseCase {
	return &manageRoleUseCase{
		userRepo: userRepository,
		roleRepo: roleRepository,
		logger:   logger,
	}
}

// UpdateRole grants or revokes a role for a user
func (uc *manageRoleUseCase) UpdateRole(req dto.ManageRoleInput) error {
	uc.logger.Info("Updating user role", "userID", req.UserID, "action", req.Action, "role", req.Role)

	// 1️⃣ Convert user ID
	userIDVO, err := valueobjects.UserIDFromString(req.UserID)
	if err != nil {
		uc.logger.Error("Invalid user ID", "userID", req.UserID, "error", err)
		return err
	}

	// 2️⃣ Fetch user
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		uc.logger.Error("Failed to fetch user", "userID", req.UserID, "error", err)
		return err
	}
	if user == nil {
		uc.logger.Warn("User not found", "userID", req.UserID)
		return errors.New("user not found")
	}

	// 3️⃣ Fetch Role entity by name
	roleName := strings.ToUpper(req.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		uc.logger.Error("Failed to fetch role", "role", roleName, "error", err)
		return err
	}
	if roleEntity == nil {
		uc.logger.Warn("Role not found", "role", roleName)
		return errors.New("role not found")
	}

	// 4️⃣ Grant or revoke role
	switch strings.ToLower(req.Action) {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID()); err != nil {
			uc.logger.Error("Failed to add role to user", "userID", req.UserID, "role", roleName, "error", err)
			return err
		}
		uc.logger.Info("Role granted to user", "userID", req.UserID, "role", roleName)
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID()); err != nil {
			uc.logger.Error("Failed to remove role from user", "userID", req.UserID, "role", roleName, "error", err)
			return err
		}
		uc.logger.Info("Role revoked from user", "userID", req.UserID, "role", roleName)
	default:
		uc.logger.Warn("Unknown action for role management", "action", req.Action)
		return errors.New("invalid action")
	}

	// 5️⃣ Update user in repository
	if err := uc.userRepo.Update(user); err != nil {
		uc.logger.Error("Failed to update user roles", "userID", req.UserID, "error", err)
		return err
	}

	uc.logger.Info("User role update successful", "userID", req.UserID)
	return nil
}

package use_cases

import (
	"errors"
	"go_auth/internal/adapters/mappers"
	"go_auth/internal/application/dto"
	"go_auth/internal/application/ports/use_cases"
	"go_auth/internal/domain/ports/repositories"
	"go_auth/internal/domain/valueobjects"
	"log/slog"
	"strings"
)

type manageRoleUseCase struct {
	userRepo   repositories.UserRepositoryPort
	uuidMapper *mappers.UUIDMapper
	logger     *slog.Logger
}

var _ use_cases.ManageRoleUseCasePort = (*manageRoleUseCase)(nil)

func NewManageRoleUseCase(
	userRepository repositories.UserRepositoryPort,
	uuidMapper *mappers.UUIDMapper,
	logger *slog.Logger,
) *manageRoleUseCase {
	return &manageRoleUseCase{
		userRepo:   userRepository,
		uuidMapper: uuidMapper,
		logger:     logger,
	}
}

func (uc *manageRoleUseCase) UpdateRole(req dto.ManageRoleInput) error {
	uc.logger.Info("Updating user role", "userID", req.UserID, "action", req.Action, "role", req.Role)

	// Convert user ID
	userIDVO, err := uc.uuidMapper.UserIdFromString(req.UserID)
	if err != nil {
		uc.logger.Error("Invalid user ID", "userID", req.UserID, "error", err)
		return err
	}

	// Fetch user
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		uc.logger.Error("Failed to fetch user", "userID", req.UserID, "error", err)
		return err
	}
	if user == nil {
		uc.logger.Warn("User not found", "userID", req.UserID)
		return errors.New("user not found")
	}

	// Parse role
	role := valueobjects.Role(strings.ToUpper(req.Role))

	// Grant or revoke role
	switch strings.ToLower(req.Action) {
	case "grant":
		user.AddRole(role)
		uc.logger.Info("Role granted to user", "userID", req.UserID, "role", role)
	case "revoke":
		user.RemoveRole(role)
		uc.logger.Info("Role revoked from user", "userID", req.UserID, "role", role)
	default:
		uc.logger.Warn("Unknown action for role management", "action", req.Action)
		return errors.New("invalid action")
	}

	// Update user in repository
	if err := uc.userRepo.Update(user); err != nil {
		uc.logger.Error("Failed to update user roles", "userID", req.UserID, "error", err)
		return err
	}

	uc.logger.Info("User role update successful", "userID", req.UserID)
	return nil
}

package usecases

import (
	"fmt"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"strings"
)

type updateRoleUseCase struct {
	userRepo ports.UserRepositoryPort
	roleRepo ports.RoleRepositoryPort
	logger   *slog.Logger
}

var _ ports.UpdateRoleUseCasePort = (*updateRoleUseCase)(nil)

func NewUpdateRoleUseCase(
	userRepo ports.UserRepositoryPort,
	roleRepo ports.RoleRepositoryPort,
	logger *slog.Logger,
) ports.UpdateRoleUseCasePort {
	return &updateRoleUseCase{
		userRepo: userRepo,
		roleRepo: roleRepo,
		logger:   logger,
	}
}

// Execute grants or revokes a role for a user
func (uc *updateRoleUseCase) Execute(req dto.ManageRoleInput) error {
	uc.logger.Info("Updating user role", "userID", req.UserID, "action", req.Action, "role", req.Role)

	// 1️⃣ Convert user ID (Domain Validation)
	userIDVO, err := valueobjects.UserIDFromString(req.UserID)
	if err != nil {
		return apperr.MapDomainErr(err)
	}

	// 2️⃣ Fetch user (Infrastructure)
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return err // Already an apperr from repository
	}
	if user == nil {
		return apperr.NewNotFoundErr("user", req.UserID)
	}

	// 3️⃣ Fetch Role entity by name (Infrastructure)
	roleName := strings.ToUpper(req.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		return err // Already an apperr from repository
	}
	if roleEntity == nil {
		return apperr.NewNotFoundErr("role", req.Role)
	}

	// 4️⃣ Grant or revoke role (Business Logic)
	action := strings.ToLower(req.Action)
	switch action {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID()); err != nil {
			// Map domain logic errors (e.g., "user already has role") to Conflict
			return apperr.NewConflictErr("role_assignment", err.Error())
		}
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID()); err != nil {
			// Map domain logic errors (e.g., "user doesn't have role") to Conflict/Not Found
			return apperr.MapDomainErr(err)
		}
	default:
		return apperr.NewValidationErr(fmt.Errorf("invalid action: %s", action))
	}

	// 5️⃣ Persist changes (Infrastructure)
	if err := uc.userRepo.Update(user); err != nil {
		return err // Already an apperr from repository
	}

	uc.logger.Info("User role update successful", "userID", req.UserID)
	return nil
}

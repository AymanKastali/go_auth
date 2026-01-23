package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"strings"
)

type updateRoleUseCase struct {
	userRepo ports.IUserRepository
	roleRepo ports.IRoleRepository
	idSvc    ports.IIDService
	clockSvc ports.IClockService
}

func NewUpdateRoleUseCase(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	idSvc ports.IIDService,
	clockSvc ports.IClockService,
) *updateRoleUseCase {
	return &updateRoleUseCase{
		userRepo: userRepo,
		roleRepo: roleRepo,
		idSvc:    idSvc,
		clockSvc: clockSvc,
	}
}

// Execute performs the role management action (grant/revoke) for a specific user.
func (uc *updateRoleUseCase) Execute(l *slog.Logger, input dto.ManageRoleInput) error {
	now, err := uc.clockSvc.Now()
	if err != nil {
		return apperr.Map(err)
	}

	l.Info("Executing role management action",
		slog.String("target_user_id", input.UserID),
		slog.String("role", input.Role),
		slog.String("action", input.Action),
	)

	userIDVO, err := valueobjects.NewUserID(input.UserID)
	if err != nil {
		return apperr.Map(err)
	}

	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		l.Error("Database error during user lookup", slog.Any("error", err))
		return apperr.Map(err)
	}
	if user == nil {
		l.Warn("Role update rejected: user not found", slog.String("user_id", input.UserID))
		return apperr.NotFound("User", input.UserID)
	}

	roleName := strings.ToUpper(input.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		l.Error("Database error during role lookup", slog.Any("error", err))
		return apperr.Map(err)
	}
	if roleEntity == nil {
		l.Warn("Role update rejected: role definition not found", slog.String("role", roleName))
		return apperr.NotFound("Role", roleName)
	}

	action := strings.ToLower(input.Action)

	l.Debug("Applying role modification",
		slog.String("action", action),
		slog.String("role_id", roleEntity.ID().String()),
	)

	switch action {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID(), now); err != nil {
			l.Warn("Role grant failed: business rule violation", slog.Any("error", err))
			return apperr.Map(err)
		}
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID(), now); err != nil {
			l.Warn("Role revoke failed: business rule violation", slog.Any("error", err))
			return apperr.Map(err)
		}
	default:
		l.Warn("Role update rejected: invalid action", slog.String("action", action))
		return apperr.Validation("invalid action type", map[string]any{"action": action})
	}

	if err := uc.userRepo.Update(user); err != nil {
		l.Error("Database error during user persistence", slog.Any("error", err))
		return apperr.Map(err)
	}

	l.Info("User role update completed successfully",
		slog.String("target_user_id", input.UserID),
		slog.String("role", roleName),
		slog.String("action", action),
	)

	return nil
}

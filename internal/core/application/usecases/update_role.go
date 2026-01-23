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
	userSvc  ports.IUserService
	userRepo ports.IUserRepository
	clockSvc ports.IClockService
}

func NewUpdateRoleUseCase(
	userSvc ports.IUserService,
	userRepo ports.IUserRepository,
	clockSvc ports.IClockService,
) *updateRoleUseCase {
	return &updateRoleUseCase{
		userSvc:  userSvc,
		userRepo: userRepo,
		clockSvc: clockSvc,
	}
}

func (uc *updateRoleUseCase) Execute(l *slog.Logger, input dto.ManageRoleInput) error {
	now, _ := uc.clockSvc.Now()

	// 1. VO Conversion (Gatekeeping)
	userID, err := valueobjects.NewUserID(input.UserID)
	if err != nil {
		return apperr.Map(err)
	}

	// 2. Retrieval
	user, err := uc.userRepo.GetByID(userID)
	if err != nil || user == nil {
		return apperr.NotFound("User", input.UserID)
	}

	// 3. Delegation to Domain Service
	action := strings.ToLower(input.Action)
	switch action {
	case "grant":
		err = uc.userSvc.AssignRole(user, input.Role, now)
	case "revoke":
		err = uc.userSvc.RemoveRole(user, input.Role, now)
	default:
		return apperr.Validation("invalid action type", nil)
	}

	if err != nil {
		l.Warn("Role update rejected", slog.Any("error", err))
		return apperr.Map(err)
	}

	// 4. Persistence
	if err := uc.userRepo.Update(user); err != nil {
		return apperr.Map(err)
	}

	l.Info("Role updated successfully", slog.String("user", user.ID().String()))
	return nil
}

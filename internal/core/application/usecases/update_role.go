package usecases

import (
	"fmt"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"log/slog"
	"strings"
)

type updateRoleUseCase struct {
	userRepo   dports.UserRepositoryPort
	roleRepo   dports.RoleRepositoryPort
	uuidParser interfaces.IUUIDParserService
	clock      interfaces.IClock
	logger     *slog.Logger
}

var _ aports.UpdateRoleUseCasePort = (*updateRoleUseCase)(nil)

func NewUpdateRoleUseCase(
	userRepo dports.UserRepositoryPort,
	roleRepo dports.RoleRepositoryPort,
	uuidParser interfaces.IUUIDParserService,
	clock interfaces.IClock,
	logger *slog.Logger,
) aports.UpdateRoleUseCasePort {
	return &updateRoleUseCase{
		userRepo:   userRepo,
		roleRepo:   roleRepo,
		uuidParser: uuidParser,
		clock:      clock,
		logger:     logger,
	}
}

// Execute grants or revokes a role for a user
func (uc *updateRoleUseCase) Execute(req dto.ManageRoleInput) error {
	uc.logger.Info("Updating user role", "userID", req.UserID, "action", req.Action, "role", req.Role)

	userIDVO, err := uc.uuidParser.ParseUserID(req.UserID)
	if err != nil {
		uc.logger.Error("Failed to generate user ID", "error", err)
		return apperr.MapDomainErr(err)
	}

	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return err
	}
	if user == nil {
		return apperr.NewNotFoundErr("user", req.UserID)
	}

	roleName := strings.ToUpper(req.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		return err
	}
	if roleEntity == nil {
		return apperr.NewNotFoundErr("role", req.Role)
	}

	action := strings.ToLower(req.Action)
	switch action {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID(), uc.clock.NowUTC()); err != nil {
			return apperr.NewConflictErr("role_assignment", err.Error())
		}
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID(), uc.clock.NowUTC()); err != nil {
			return apperr.MapDomainErr(err)
		}
	default:
		return apperr.NewValidationErr(fmt.Errorf("invalid action: %s", action))
	}

	if err := uc.userRepo.Update(user); err != nil {
		return err
	}

	uc.logger.Info("User role update successful", "userID", req.UserID)
	return nil
}

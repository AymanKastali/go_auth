package usecases

import (
	"errors"
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

func (uc *updateRoleUseCase) Execute(req dto.ManageRoleInput) error {
	uc.logger.Info("Updating user role", "userID", req.UserID, "action", req.Action, "role", req.Role)

	// 1. Parsing (Validation Intent)
	userIDVO, err := uc.uuidParser.ParseUserID(req.UserID)
	if err != nil {
		uc.logger.Error("Failed to parse user ID", "error", err)
		return apperr.Validation(err)
	}

	// 2. Resource Fetching (NotFound Intent)
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return apperr.Internal(err)
	}
	if user == nil {
		return apperr.NotFound(nil)
	}

	roleName := strings.ToUpper(req.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		return apperr.Internal(err)
	}
	if roleEntity == nil {
		return apperr.NotFound(nil)
	}

	now := uc.clock.NowUTC()
	action := strings.ToLower(req.Action)

	// 3. Domain Logic (Conflict or Validation Intent)
	switch action {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID(), now); err != nil {
			// Granting a role the user already has is a state Conflict
			return apperr.Conflict(err)
		}
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID(), now); err != nil {
			// Revoking a non-existent role or the last role is a business rule Validation
			return apperr.Validation(err)
		}
	default:
		// Invalid actions from the DTO level are typically Internal or Validation
		// depending on where the check happens.
		return apperr.Validation(errors.New("invalid action: " + action))
	}

	// 4. Persistence (Internal Intent)
	if err := uc.userRepo.Update(user); err != nil {
		return apperr.Internal(err)
	}

	uc.logger.Info("User role update successful", "userID", req.UserID)
	return nil
}

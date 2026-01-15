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
	clock    ports.IClockService
	logger   *slog.Logger
}

func NewUpdateRoleUseCase(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	idSvc ports.IIDService,
	clock ports.IClockService,
	logger *slog.Logger,
) *updateRoleUseCase {
	return &updateRoleUseCase{
		userRepo: userRepo,
		roleRepo: roleRepo,
		idSvc:    idSvc,
		clock:    clock,
		logger:   logger,
	}
}

func (uc *updateRoleUseCase) Execute(traceID string, req dto.ManageRoleInput) error {
	uc.logger.Info("Attempting to update user role",
		"trace_id", traceID,
		"user_id", req.UserID,
		"action", req.Action,
		"role", req.Role,
	)

	// 1. Orchestration Validation
	if !uc.idSvc.IsValid(req.UserID) {
		return apperr.Validation("invalid user id format", traceID, map[string]any{"user_id": req.UserID})
	}

	// 2. Resource Fetching
	userIDVO := valueobjects.ReconstituteUserID(req.UserID)
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return apperr.Map(err, traceID)
	}
	if user == nil {
		// Proper Factory call: (resource, id, traceID)
		return apperr.NotFound("User", req.UserID, traceID)
	}

	roleName := strings.ToUpper(req.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		return apperr.Map(err, traceID)
	}
	if roleEntity == nil {
		return apperr.NotFound("Role", roleName, traceID)
	}

	// 3. Domain Logic Execution
	now := uc.clock.Now().UTC()
	action := strings.ToLower(req.Action)

	switch action {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID(), now); err != nil {
			// Maps derr.ErrRoleAlreadyAssigned to apperr.TypeConflict
			return apperr.Map(err, traceID)
		}
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID(), now); err != nil {
			// Maps derr.ErrMinimumRolesRequirement to apperr.TypeValidation
			return apperr.Map(err, traceID)
		}
	default:
		return apperr.Validation("invalid action type", traceID, map[string]any{"action": action})
	}

	// 4. Persistence
	if err := uc.userRepo.Update(user); err != nil {
		return apperr.Map(err, traceID)
	}

	uc.logger.Info("User role update successful", "trace_id", traceID, "user_id", req.UserID)
	return nil
}

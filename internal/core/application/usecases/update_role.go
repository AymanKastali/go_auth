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

func (uc *updateRoleUseCase) Execute(requestID string, req dto.ManageRoleInput) error {
	userIDReq := req.UserID

	uc.logger.Info("Updating user role",
		"request_id", requestID,
		"userID", userIDReq,
		"action", req.Action,
		"role", req.Role,
	)
	if !uc.idSvc.IsValid(userIDReq) {
		return apperr.Invalid("invalid user id format", requestID, nil)
	}

	userIDVO := valueobjects.ReconstituteUserID(userIDReq)

	// 2. Resource Fetching
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return apperr.FromDomain(err, requestID)
	}
	if user == nil {
		return apperr.NotFound("target user not found", requestID, nil)
	}

	roleName := strings.ToUpper(req.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		return apperr.FromDomain(err, requestID)
	}
	if roleEntity == nil {
		return apperr.NotFound("specified role not found", requestID, nil)
	}

	now := uc.clock.Now().UTC()
	action := strings.ToLower(req.Action)

	// 3. Domain Logic (Delegating mapping to FromDomain)
	switch action {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID(), now); err != nil {
			// e.g., if user already has the role, AddRoleID returns derr.ErrStatusAlready
			return apperr.FromDomain(err, requestID)
		}
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID(), now); err != nil {
			// e.g., if it's the last role, RemoveRoleID returns a domain rule violation
			return apperr.FromDomain(err, requestID)
		}
	default:
		return apperr.Invalid("invalid action: "+action, requestID, nil)
	}

	// 4. Persistence
	if err := uc.userRepo.Update(user); err != nil {
		return apperr.FromDomain(err, requestID)
	}

	uc.logger.Info("User role update successful", "request_id", requestID, "userID", userIDReq)
	return nil
}

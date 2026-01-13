package usecases

import (
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

func (uc *updateRoleUseCase) Execute(traceID string, req dto.ManageRoleInput) error {
	uc.logger.Info("Updating user role",
		"trace_id", traceID,
		"userID", req.UserID,
		"action", req.Action,
		"role", req.Role)

	// 1. Parsing Input
	userIDVO, err := uc.uuidParser.ParseUserID(req.UserID)
	if err != nil {
		uc.logger.Error("Failed to parse user ID", "trace_id", traceID, "error", err)
		return apperr.BadRequest("invalid user id format", traceID, err)
	}

	// 2. Resource Fetching
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return apperr.FromDomain(err, traceID)
	}
	if user == nil {
		return apperr.NotFound("target user not found", traceID, nil)
	}

	roleName := strings.ToUpper(req.Role)
	roleEntity, err := uc.roleRepo.GetByName(roleName)
	if err != nil {
		return apperr.FromDomain(err, traceID)
	}
	if roleEntity == nil {
		return apperr.NotFound("specified role not found", traceID, nil)
	}

	now := uc.clock.NowUTC()
	action := strings.ToLower(req.Action)

	// 3. Domain Logic (Delegating mapping to FromDomain)
	switch action {
	case "grant":
		if err := user.AddRoleID(roleEntity.ID(), now); err != nil {
			// e.g., if user already has the role, AddRoleID returns derr.ErrStatusAlready
			return apperr.FromDomain(err, traceID)
		}
	case "revoke":
		if err := user.RemoveRoleID(roleEntity.ID(), now); err != nil {
			// e.g., if it's the last role, RemoveRoleID returns a domain rule violation
			return apperr.FromDomain(err, traceID)
		}
	default:
		return apperr.BadRequest("invalid action: "+action, traceID, nil)
	}

	// 4. Persistence
	if err := uc.userRepo.Update(user); err != nil {
		return apperr.FromDomain(err, traceID)
	}

	uc.logger.Info("User role update successful", "trace_id", traceID, "userID", req.UserID)
	return nil
}

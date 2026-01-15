package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type authUserUseCase struct {
	userRepo ports.IUserRepository
	roleRepo ports.IRoleRepository
	idSvc    ports.IIDService
	logger   *slog.Logger
}

func NewAuthUserUseCase(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	idSvc ports.IIDService,
	logger *slog.Logger,
) *authUserUseCase {
	return &authUserUseCase{
		userRepo: userRepo,
		roleRepo: roleRepo,
		idSvc:    idSvc,
		logger:   logger,
	}
}

func (uc *authUserUseCase) Execute(traceID string, userID string) (*dto.AuthUser, error) {
	uc.logger.Info("Compiling user authentication data", "user_id", userID, "trace_id", traceID)

	// 1. Validation
	if !uc.idSvc.IsValid(userID) {
		return nil, apperr.Validation("invalid user id format", traceID, map[string]any{"user_id": userID})
	}
	userIDVO := valueobjects.ReconstituteUserID(userID)

	// 2. Fetch User
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	if user == nil {
		return nil, apperr.NotFound("User", userID, traceID)
	}

	// 3. Hydrate Role Names (Strict Integrity Check)
	roleIDs := user.RoleIDs()
	roles := make([]string, len(roleIDs))

	for i, rID := range roleIDs {
		role, err := uc.roleRepo.GetByID(rID)
		if err != nil {
			return nil, apperr.Map(err, traceID)
		}

		if role == nil {
			// STRICT: We do not use placeholders. A missing role reference is a 500 Internal error.
			uc.logger.Error("DATA INTEGRITY VIOLATION: user assigned to non-existent role",
				"user_id", userID,
				"role_id", rID.Value(),
				"trace_id", traceID,
			)
			return nil, apperr.Internal("system data integrity violation: role not found", traceID, nil)
		}
		roles[i] = role.Name()
	}

	return &dto.AuthUser{
		ID:        user.ID().Value(),
		Email:     user.Email().Value(),
		Status:    string(user.Status()),
		Roles:     roles,
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}, nil
}

package usecases

import (
	"context"
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
}

func NewAuthUserUseCase(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	idSvc ports.IIDService,
) *authUserUseCase {
	return &authUserUseCase{
		userRepo: userRepo,
		roleRepo: roleRepo,
		idSvc:    idSvc,
	}
}

func (uc *authUserUseCase) Execute(c context.Context, userID string) (*dto.AuthUser, error) {
	req := dto.FromContext(c)
	l := req.Logger

	l.Info("Executing auth user profile retrieval", slog.String("target_user_id", userID))

	if !uc.idSvc.IsValid(userID) {
		l.Warn("Invalid user ID format provided", slog.String("user_id", userID))
		return nil, apperr.Validation("invalid user id format", map[string]any{"user_id": userID})
	}

	userIDVO := valueobjects.ReconstituteUserID(userID)

	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		l.Error("Database error during user lookup", slog.String("user_id", userID), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	if user == nil {
		l.Warn("User profile not found", slog.String("user_id", userID))
		return nil, apperr.NotFound("User", userID)
	}

	roleIDs := user.RoleIDs()
	roles := make([]string, len(roleIDs))

	l.Debug("Hydrating user roles", slog.Int("role_count", len(roleIDs)))

	for i, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			l.Error("Database error during role lookup",
				slog.String("user_id", userID),
				slog.String("role_id", roleID.Value()),
				slog.Any("error", err),
			)
			return nil, apperr.Map(err)
		}

		if role == nil {
			l.Error("CRITICAL: Data integrity violation - role not found",
				slog.String("user_id", userID),
				slog.String("missing_role_id", roleID.Value()),
			)
			return nil, apperr.Internal("system data integrity violation: role not found", nil)
		}
		roles[i] = role.Name()
	}

	l.Info("Successfully compiled user authentication data", slog.String("user_id", userID))

	return &dto.AuthUser{
		ID:        user.ID().Value(),
		Email:     user.Email().Value(),
		Status:    string(user.Status()),
		Roles:     roles,
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}, nil
}

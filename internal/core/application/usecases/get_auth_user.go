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

func (uc *authUserUseCase) Execute(requestID string, userID string) (*dto.AuthUser, error) {
	if !uc.idSvc.IsValid(userID) {
		return nil, apperr.Invalid("invalid user id format", requestID, nil)
	}
	userIDVO := valueobjects.ReconstituteUserID(userID)

	// 2. Fetching User
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		uc.logger.Error("failed to retrieve user from repository",
			slog.String("user_id", userID),
			slog.String("request_id", requestID),
			slog.Any("error", err))
		return nil, apperr.FromDomain(err, requestID)
	}

	if user == nil {
		uc.logger.Info("authentication attempted for non-existent user",
			slog.String("user_id", userID),
			slog.String("request_id", requestID))
		return nil, apperr.NotFound("user not found", requestID, nil)
	}

	// 3. Fetching Roles
	roleIDs := user.RoleIDs()
	roles := make([]string, len(roleIDs))

	for i, rID := range roleIDs {
		role, err := uc.roleRepo.GetByID(rID)
		if err != nil {
			uc.logger.Error("critical failure fetching role details",
				slog.String("user_id", userID),
				slog.Any("role_id", rID),
				slog.String("request_id", requestID),
				slog.Any("error", err))
			return nil, apperr.FromDomain(err, requestID)
		}

		if role == nil {
			uc.logger.Warn("user assigned to non-existent role",
				slog.String("user_id", userID),
				slog.Any("role_id", rID),
				slog.String("request_id", requestID))
			roles[i] = "UNKNOWN"
			continue
		}
		roles[i] = role.Name()
	}

	uc.logger.Info("user authentication data successfully compiled",
		slog.String("user_id", userID),
		slog.String("request_id", requestID))

	return &dto.AuthUser{
		ID:        user.ID().Value(),
		Email:     user.Email().Value(),
		Status:    string(user.Status()),
		Roles:     roles,
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}, nil
}

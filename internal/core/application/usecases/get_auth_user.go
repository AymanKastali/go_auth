package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"log/slog"
)

type authUserUseCase struct {
	userRepo   dports.UserRepositoryPort
	roleRepo   dports.RoleRepositoryPort
	uuidParser interfaces.IUUIDParserService
	logger     *slog.Logger
}

var _ aports.AuthUserUseCasePort = (*authUserUseCase)(nil)

func NewAuthUserUseCase(
	userRepo dports.UserRepositoryPort,
	roleRepo dports.RoleRepositoryPort,
	uuidParser interfaces.IUUIDParserService,
	logger *slog.Logger,
) aports.AuthUserUseCasePort {
	return &authUserUseCase{
		userRepo:   userRepo,
		roleRepo:   roleRepo,
		uuidParser: uuidParser,
		logger:     logger,
	}
}

func (uc *authUserUseCase) Execute(userID string) (*dto.AuthUser, error) {
	// 1. Parsing Input
	userIDVO, err := uc.uuidParser.ParseUserID(userID)
	if err != nil {
		uc.logger.Warn("invalid user id format provided",
			slog.String("user_id", userID),
			slog.Any("error", err))
		return nil, apperr.Validation(err)
	}

	// 2. Fetching User
	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		uc.logger.Error("failed to retrieve user from repository",
			slog.String("user_id", userID),
			slog.Any("error", err))
		return nil, apperr.Internal(err)
	}

	if user == nil {
		uc.logger.Info("authentication attempted for non-existent user",
			slog.String("user_id", userID))
		return nil, apperr.NotFound(nil)
	}

	// 3. Fetching Roles
	roleIDs := user.RoleIDs()
	roles := make([]string, len(roleIDs))

	uc.logger.Debug("fetching roles for user",
		slog.String("user_id", userID),
		slog.Int("count", len(roleIDs)))

	for i, rID := range roleIDs {
		role, err := uc.roleRepo.GetByID(rID)
		if err != nil {
			uc.logger.Error("critical failure fetching role details",
				slog.String("user_id", userID),
				slog.Any("role_id", rID),
				slog.Any("error", err))
			return nil, apperr.Internal(err)
		}

		if role == nil {
			uc.logger.Warn("user assigned to non-existent role",
				slog.String("user_id", userID),
				slog.Any("role_id", rID))
			roles[i] = "UNKNOWN"
			continue
		}
		roles[i] = role.Name()
	}

	uc.logger.Info("user authentication data successfully compiled",
		slog.String("user_id", userID),
		slog.Any("roles", roles))

	return &dto.AuthUser{
		ID:        user.ID().Value(),
		Email:     user.Email().Value(),
		Status:    string(user.Status()),
		Roles:     roles,
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}, nil
}

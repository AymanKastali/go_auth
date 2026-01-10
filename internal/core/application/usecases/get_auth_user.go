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
	userIDVO, err := uc.uuidParser.ParseUserID(userID)
	if err != nil {
		uc.logger.Error("Failed to generate user ID", "error", err)
		return nil, apperr.NewInternalErr("failed to generate user id")
	}

	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, apperr.NewNotFoundErr("user", userID)
	}

	roleIDs := user.RoleIDs()
	roles := make([]string, len(roleIDs))
	for i, rID := range roleIDs {
		role, err := uc.roleRepo.GetByID(rID)
		if err != nil {
			uc.logger.Error("Failed to fetch role", "roleID", rID, "error", err)
			return nil, apperr.NewInternalErr("failed to fetch user roles")
		}
		if role == nil {
			uc.logger.Warn("Role not found for user", "roleID", rID)
			roles[i] = "UNKNOWN"
			continue
		}
		roles[i] = role.Name()
	}

	return &dto.AuthUser{
		ID:        user.ID().Value(),
		Email:     user.Email().String(),
		Status:    string(user.Status()),
		Roles:     roles,
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}, nil
}

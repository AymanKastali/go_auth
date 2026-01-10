package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type registerUseCase struct {
	userRepo       dports.UserRepositoryPort
	roleRepo       dports.RoleRepositoryPort
	passwordHasher aports.HashPasswordServicePort
	uuidGenerator  interfaces.IUUIDGeneratorService
	logger         *slog.Logger
}

var _ aports.RegisterUseCasePort = (*registerUseCase)(nil)

func NewRegisterUseCase(
	userRepo dports.UserRepositoryPort,
	roleRepo dports.RoleRepositoryPort,
	passwordHasher aports.HashPasswordServicePort,
	uuidGenerator interfaces.IUUIDGeneratorService,
	logger *slog.Logger,
) aports.RegisterUseCasePort {
	return &registerUseCase{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		uuidGenerator:  uuidGenerator,
		logger:         logger,
	}
}

func (uc *registerUseCase) Execute(email, password string) (*dto.RegisteredUserDTO, error) {
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	hash, err := uc.passwordHasher.Hash(password)
	if err != nil {
		uc.logger.Error("Password hashing failed", "error", err)
		return nil, apperr.NewInternalErr("security component failure")
	}
	pw := valueobjects.NewHashedPassword(hash)

	userRole, err := uc.roleRepo.GetByName("user")
	if err != nil {
		return nil, err
	}
	if userRole == nil {
		uc.logger.Error("System misconfiguration: user role missing")
		return nil, apperr.NewInternalErr("default role assignment failed")
	}

	userID, err := uc.uuidGenerator.NewUserID()
	if err != nil {
		uc.logger.Error("Failed to generate user ID", "error", err)
		return nil, apperr.NewInternalErr("failed to generate user id")
	}

	user, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{userRole.ID()},
		time.Now().UTC(),
	)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	if err := uc.userRepo.Save(user); err != nil {
		return nil, err
	}

	return &dto.RegisteredUserDTO{
		UserID: user.ID().Value(),
		Email:  user.Email().Value(),
	}, nil
}

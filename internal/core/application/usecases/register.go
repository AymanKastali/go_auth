package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type registerUseCase struct {
	userRepo       ports.IUserRepository
	roleRepo       ports.IRoleRepository
	passwordHasher ports.IPasswordHasherService
	idSvc          ports.IIDService
	clockSvc       ports.IClockService
}

func NewRegisterUseCase(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	passwordHasher ports.IPasswordHasherService,
	idSvc ports.IIDService,
	clockSvc ports.IClockService,
) *registerUseCase {
	return &registerUseCase{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		idSvc:          idSvc,
		clockSvc:       clockSvc,
	}
}

func (uc *registerUseCase) Execute(
	c context.Context,
	email, password string,
) (*dto.RegisteredUserDTO, error) {
	req := dto.GetRequestContext(c)
	now := uc.clockSvc.Now().UTC()

	req.Logger.Info("Executing user registration", slog.String("email", email))

	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		req.Logger.Warn("Registration failed: invalid email format", slog.String("email", email))
		return nil, apperr.Map(err)
	}

	existingUser, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		req.Logger.Error("Database error during email uniqueness check", slog.Any("error", err))
		return nil, apperr.Map(err)
	}
	if existingUser != nil {
		req.Logger.Warn("Registration rejected: email already exists", slog.String("email", email))
		return nil, apperr.Conflict("an account with this email already exists", nil)
	}

	rawPwd, err := valueobjects.NewRawPassword(password)
	if err != nil {
		return nil, apperr.Map(err)
	}

	hashedPwd, err := uc.passwordHasher.Hash(rawPwd)
	if err != nil {
		req.Logger.Error("Cryptography service failure during hashing", slog.Any("error", err))
		return nil, apperr.Internal("failed to secure password", err)
	}

	userRole, err := uc.roleRepo.GetByName("user")
	if err != nil {
		req.Logger.Error("Database error during default role lookup", slog.Any("error", err))
		return nil, apperr.Map(err)
	}
	if userRole == nil {
		req.Logger.Error("CRITICAL: Missing system configuration - USER role not found")
		return nil, apperr.Internal("required system configuration missing", nil)
	}

	userID, err := valueobjects.NewUserID(uc.idSvc.Generate())
	if err != nil {
		req.Logger.Error("Identity generation service failure", slog.Any("error", err))
		return nil, apperr.Internal("identity generation failed", err)
	}

	user, err := aggregates.NewUser(
		userID,
		emailVO,
		hashedPwd,
		valueobjects.UserActive,
		[]valueobjects.RoleID{userRole.ID()},
		now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	if err := uc.userRepo.Create(user); err != nil {
		req.Logger.Error("Database error during user creation", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	req.Logger.Info("User registration completed successfully",
		slog.String("user_id", user.ID().Value()),
		slog.Duration("duration", uc.clockSvc.Now().Sub(now)),
	)

	return &dto.RegisteredUserDTO{
		UserID: user.ID().Value(),
		Email:  user.Email().Value(),
	}, nil
}

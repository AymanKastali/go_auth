package usecases

import (
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
	clock          ports.IClockService
	logger         *slog.Logger
}

func NewRegisterUseCase(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	passwordHasher ports.IPasswordHasherService,
	idSvc ports.IIDService,
	clock ports.IClockService,
	logger *slog.Logger,
) *registerUseCase {
	return &registerUseCase{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		idSvc:          idSvc,
		clock:          clock,
		logger:         logger,
	}
}

func (uc *registerUseCase) Execute(traceID, email, password string) (*dto.RegisteredUserDTO, error) {
	l := uc.logger.With(
		slog.String("trace_id", traceID),
		slog.String("use_case", "RegisterUser"),
	)

	start := uc.clock.Now()
	l.Info("registration_started", slog.String("email", email))

	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	existingUser, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}
	if existingUser != nil {
		// Log as Warn: This is a meaningful business event (potential bot or user error)
		l.Warn("registration_rejected",
			slog.String("reason", "email_exists"),
			slog.String("email", email),
		)
		return nil, apperr.Conflict("an account with this email already exists", traceID, nil)
	}

	rawPwd, err := valueobjects.NewRawPassword(password)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	hashedPwd, err := uc.passwordHasher.Hash(rawPwd)
	if err != nil {
		l.Error("cryptography_service_failure", slog.Any("error", err))
		return nil, apperr.Internal("failed to secure password", traceID, err)
	}

	userRole, err := uc.roleRepo.GetByName("USER")
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}
	if userRole == nil {
		l.Error("missing_critical_configuration",
			slog.String("resource", "USER_role"),
			slog.String("impact", "user_cannot_register"),
		)
		return nil, apperr.Internal("required system configuration missing", traceID, nil)
	}

	userID, err := valueobjects.NewUserID(uc.idSvc.Generate())
	if err != nil {
		return nil, apperr.Internal("identity generation failed", traceID, err)
	}

	user, err := aggregates.NewUser(
		userID,
		emailVO,
		hashedPwd,
		valueobjects.UserActive,
		[]valueobjects.RoleID{userRole.ID()},
		uc.clock.Now().UTC(),
	)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	if err := uc.userRepo.Create(user); err != nil {
		return nil, apperr.Map(err, traceID)
	}

	l.Info("registration_completed",
		slog.String("user_id", user.ID().Value()),
		slog.String("latency", uc.clock.Now().Sub(start).String()),
	)

	return &dto.RegisteredUserDTO{
		UserID: user.ID().Value(),
		Email:  user.Email().Value(),
	}, nil
}

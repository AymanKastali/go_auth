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
	passwordHasher ports.IPasswordHasherService
	idSvc          ports.IIDService
	clockSvc       ports.IClockService
	regPolicy      ports.UserRegistrationPolicy
}

func NewRegisterUseCase(
	userRepo ports.IUserRepository,
	passwordHasher ports.IPasswordHasherService,
	idSvc ports.IIDService,
	clockSvc ports.IClockService,
	regPolicy ports.UserRegistrationPolicy,
) *registerUseCase {
	return &registerUseCase{
		userRepo:       userRepo,
		passwordHasher: passwordHasher,
		idSvc:          idSvc,
		clockSvc:       clockSvc,
		regPolicy:      regPolicy,
	}
}

func (uc *registerUseCase) Execute(
	c context.Context,
	email, password string,
) (*dto.RegisteredUserDTO, error) {

	req := dto.FromContext(c)
	l := req.Logger
	start := uc.clockSvc.Now().UTC()

	l.Info(
		"User registration started",
		slog.String("email", email),
	)

	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		l.Warn(
			"User registration failed: invalid email",
			slog.String("email", email),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	if err := uc.regPolicy.Validate(emailVO); err != nil {
		l.Warn(
			"User registration rejected by policy",
			slog.String("email", emailVO.Value()),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	rawPwd, err := valueobjects.NewRawPassword(password)
	if err != nil {
		l.Warn(
			"User registration failed: invalid password",
			slog.String("email", emailVO.Value()),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	hashedPwd, err := uc.passwordHasher.Hash(rawPwd)
	if err != nil {
		l.Error(
			"User registration failed: password hashing error",
			slog.String("email", emailVO.Value()),
			slog.Any("error", err),
		)
		return nil, apperr.Internal("failed to secure password", err)
	}

	roles, err := uc.regPolicy.DefaultRoles()
	if err != nil {
		l.Error(
			"User registration failed: default role resolution error",
			slog.String("email", emailVO.Value()),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	userID, err := valueobjects.NewUserID(uc.idSvc.Generate())
	if err != nil {
		l.Error(
			"User registration failed: user id generation error",
			slog.Any("error", err),
		)
		return nil, apperr.Internal("identity generation failed", err)
	}

	user, err := aggregates.NewUser(
		userID,
		emailVO,
		hashedPwd,
		valueobjects.UserActive,
		roles,
		start,
	)
	if err != nil {
		l.Error(
			"User registration failed: aggregate creation error",
			slog.String("user_id", userID.Value()),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	if err := uc.userRepo.Create(user); err != nil {
		l.Error(
			"User registration failed: persistence error",
			slog.String("user_id", user.ID().Value()),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	duration := uc.clockSvc.Now().Sub(start)

	l.Info(
		"User registration completed successfully",
		slog.String("user_id", user.ID().Value()),
		slog.String("email", user.Email().Value()),
		slog.Duration("duration", duration),
	)

	return &dto.RegisteredUserDTO{
		UserID: user.ID().Value(),
		Email:  user.Email().Value(),
	}, nil
}

package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type RegisterUseCase struct {
	userRepo    ports.IUserRepository
	userFactory ports.IUserFactory
	clockSvc    ports.IClockService
}

func NewRegisterUseCase(
	userRepo ports.IUserRepository,
	userFactory ports.IUserFactory,
	clockSvc ports.IClockService,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepo:    userRepo,
		userFactory: userFactory,
		clockSvc:    clockSvc,
	}
}

func (uc *RegisterUseCase) Execute(ctx context.Context, emailStr, passwordStr string) (*dto.RegisteredUserDTO, error) {
	now, err := uc.clockSvc.Now()
	if err != nil {
		return nil, apperr.Map(err)
	}

	req := dto.FromContext(ctx)
	l := req.Logger

	l.Info("User registration started", slog.String("email", emailStr))

	emailVO, err := valueobjects.NewEmail(emailStr)
	if err != nil {
		l.Warn("Invalid email", slog.String("email", emailStr), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	rawPwd, err := valueobjects.NewRawPassword(passwordStr)
	if err != nil {
		l.Warn("Invalid password", slog.String("email", emailStr), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	user, err := uc.userFactory.New(emailVO, rawPwd, now)
	if err != nil {
		l.Warn("User creation rejected by domain policy", slog.String("email", emailStr), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	if err := uc.userRepo.Create(user); err != nil {
		l.Error("User persistence failed", slog.String("user_id", user.ID().String()), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	duration := time.Since(now.Time())
	l.Info("User registration completed successfully",
		slog.String("user_id", user.ID().String()),
		slog.String("email", user.Email().String()),
		slog.String("duration", duration.String()),
	)

	return &dto.RegisteredUserDTO{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}

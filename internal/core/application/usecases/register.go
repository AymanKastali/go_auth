package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type RegisterUseCase struct {
	userRepo ports.IUserRepository
	userSvc  ports.IUserService
	clockSvc ports.IClockService
}

func NewRegisterUseCase(
	userRepo ports.IUserRepository,
	userSvc ports.IUserService,
	clockSvc ports.IClockService,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepo: userRepo,
		userSvc:  userSvc,
		clockSvc: clockSvc,
	}
}

func (uc *RegisterUseCase) Execute(l *slog.Logger, emailStr, passwordStr string) (*dto.RegisteredUserDTO, error) {
	// 1. Initial Context
	l.Info("Attempting user registration", slog.String("email", emailStr))

	now, _ := uc.clockSvc.Now()

	// 2. VO Gatekeeping
	email, err := valueobjects.NewEmail(emailStr)
	if err != nil {
		l.Warn("Registration failed: invalid email format", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	rawPwd, err := valueobjects.NewRawPassword(passwordStr)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 3. Domain Service Call
	user, err := uc.userSvc.RegisterUser(email, rawPwd, now)
	if err != nil {
		// We log as Warn because this is a business/domain rejection, not a system crash
		l.Warn("Registration rejected by domain rules",
			slog.String("email", emailStr),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	// 4. Infrastructure/Persistence
	if err := uc.userRepo.Save(user); err != nil {
		// We log as Error because this is a technical failure (DB down, etc.)
		l.Error("Failed to persist new user",
			slog.String("user_id", user.ID().String()),
			slog.Any("error", err),
		)
		return nil, apperr.Map(err)
	}

	l.Info("User registered successfully", slog.String("user_id", user.ID().String()))

	return &dto.RegisteredUserDTO{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}

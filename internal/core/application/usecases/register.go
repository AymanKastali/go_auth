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
	passwordHasher ports.IPasswordService
	idSvc          ports.IIDService
	clock          ports.IClockService
	logger         *slog.Logger
}

func NewRegisterUseCase(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	passwordHasher ports.IPasswordService,
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
	uc.logger.Info("Starting user registration", "email", email, "trace_id", traceID)

	// 1. Email Value Object (Validation)
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		// Maps derr.CodeValidation to apperr.TypeValidation
		return nil, apperr.Map(err, traceID)
	}

	// 2. Existence Check
	existingUser, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}
	if existingUser != nil {
		uc.logger.Warn("Registration attempt with existing email", "email", email, "trace_id", traceID)
		return nil, apperr.Conflict("an account with this email already exists", traceID, nil)
	}

	// 3. Cryptography (Orchestration)
	hash, err := uc.passwordHasher.Hash(password)
	if err != nil {
		uc.logger.Error("Password hashing failed", "trace_id", traceID, "error", err)
		return nil, apperr.Internal("cryptography failure during registration", traceID, err)
	}

	pw, err := valueobjects.NewHashedPassword(hash)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	// 4. Role Fetching (Dependency Check)
	userRole, err := uc.roleRepo.GetByName("USER") // Assuming standardized uppercase names
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}
	if userRole == nil {
		uc.logger.Error("System misconfiguration: 'USER' role missing", "trace_id", traceID)
		return nil, apperr.Internal("required system configuration missing", traceID, nil)
	}

	// 5. Aggregate Instantiation
	userID, err := valueobjects.NewUserID(uc.idSvc.Generate())
	if err != nil {
		return nil, apperr.Internal("identity generation failed", traceID, err)
	}

	user, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{userRole.ID()},
		uc.clock.Now().UTC(),
	)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	// 6. Persistence
	if err := uc.userRepo.Create(user); err != nil {
		// Automatically handles 409 Conflict if DB returns duplicate key via Map
		return nil, apperr.Map(err, traceID)
	}

	uc.logger.Info("User registration successful", "user_id", user.ID().Value(), "trace_id", traceID)

	return &dto.RegisteredUserDTO{
		UserID: user.ID().Value(),
		Email:  user.Email().Value(),
	}, nil
}

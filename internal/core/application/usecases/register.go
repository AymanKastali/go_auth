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

func (uc *registerUseCase) Execute(requestID, email, password string) (*dto.RegisteredUserDTO, error) {
	uc.logger.Info("Starting user registration", "email", email, "request_id", requestID)

	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	existingUser, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}
	if existingUser != nil {
		uc.logger.Warn("Registration attempt with existing email", "email", email, "request_id", requestID)
		return nil, apperr.Conflict("an account with this email already exists", requestID, nil)
	}

	// 3. Hash Password
	hash, err := uc.passwordHasher.Hash(password)
	if err != nil {
		uc.logger.Error("Password hashing failed", "request_id", requestID, "error", err)
		return nil, apperr.Internal("security service failure", requestID, err)
	}

	pw, err := valueobjects.NewHashedPassword(hash)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	// 4. Role Fetching (System Dependency)
	userRole, err := uc.roleRepo.GetByName("user")
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}
	if userRole == nil {
		uc.logger.Error("System misconfiguration: 'user' role missing", "request_id", requestID)
		return nil, apperr.Internal("required system configuration missing", requestID, nil)
	}

	userID, err := valueobjects.NewUserID(uc.idSvc.Generate())
	if err != nil {
		return nil, apperr.Internal("failed to generate user identity", requestID, err)
	}

	// 5. Aggregate Instantiation (Logic/Invariants)
	user, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{userRole.ID()},
		uc.clock.Now().UTC(),
	)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	// 6. Persistence
	if err := uc.userRepo.Create(user); err != nil {
		// If the DB returns a unique constraint error, repo maps it to derr.ErrDuplicate
		// which FromDomain handles perfectly as a Conflict (409).
		return nil, apperr.FromDomain(err, requestID)
	}

	return &dto.RegisteredUserDTO{
		UserID: user.ID().Value(),
		Email:  user.Email().Value(),
	}, nil
}

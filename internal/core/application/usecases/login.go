package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type loginUseCase struct {
	userRepo       dports.UserRepositoryPort
	refreshRepo    dports.RefreshTokenRepositoryPort
	deviceRepo     dports.DeviceRepositoryPort
	roleRepo       dports.RoleRepositoryPort
	passwordHasher aports.HashPasswordServicePort
	tokenService   aports.TokenServicePort
	uuidGenerator  interfaces.IUUIDGeneratorService
	uuidParser     interfaces.IUUIDParserService
	clock          interfaces.IClock
	logger         *slog.Logger
}

var _ aports.LoginUseCasePort = (*loginUseCase)(nil)

func NewLoginUseCase(
	userRepo dports.UserRepositoryPort,
	refreshRepo dports.RefreshTokenRepositoryPort,
	deviceRepo dports.DeviceRepositoryPort,
	roleRepo dports.RoleRepositoryPort,
	passwordHasher aports.HashPasswordServicePort,
	tokenService aports.TokenServicePort,
	uuidGenerator interfaces.IUUIDGeneratorService,
	uuidParser interfaces.IUUIDParserService,
	clock interfaces.IClock,
	logger *slog.Logger,
) aports.LoginUseCasePort {
	return &loginUseCase{
		userRepo:       userRepo,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		uuidGenerator:  uuidGenerator,
		uuidParser:     uuidParser,
		clock:          clock,
		logger:         logger,
	}
}

func (uc *loginUseCase) Execute(
	requestID string, // Pass requestID as a string to keep the layer pure
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {
	uc.logger.Info("Starting user login", "email", email, "request_id", requestID)
	now := uc.clock.Now().UTC()

	// 1. Authenticate User
	user, err := uc.authenticate(requestID, email, password)
	if err != nil {
		return nil, err
	}

	// 2. Resolve Device
	device, err := uc.resolveDevice(requestID, user.ID(), deviceIDStr, deviceName, userAgent, ipAddress, now)
	if err != nil {
		return nil, err
	}

	// 3. Fetch Permissions
	roleNames, err := uc.fetchRoleNames(requestID, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Generate Token ID
	tokenID, err := uc.uuidGenerator.NewTokenID()
	if err != nil {
		return nil, apperr.Internal("failed to generate unique token identifier", requestID, err)
	}

	// 5. Finalize Session
	return uc.issueTokensAndSaveSession(requestID, tokenID, user, device, roleNames, now)
}

func (uc *loginUseCase) authenticate(requestID, email, password string) (*aggregates.User, error) {
	emailVO := valueobjects.ReconstituteEmail(email)
	user, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	// Security: Use a generic error for both "user not found" and "wrong password"
	if user == nil || !uc.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		return nil, apperr.Unauthorized("invalid credentials", requestID, nil)
	}

	return user, nil
}

func (uc *loginUseCase) resolveDevice(
	requestID string,
	userID valueobjects.UserID,
	deviceIDStr, name, ua, ip string,
	currentTime time.Time,
) (*entities.Device, error) {

	deviceID, err := uc.uuidParser.ParseDeviceID(deviceIDStr)
	if err != nil {
		return nil, apperr.Invalid("invalid device format", requestID, err)
	}

	device, err := uc.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	if device == nil {
		device, err = entities.NewDevice(deviceID, userID, &name, &ua, &ip, currentTime)
		if err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}
		device.Activate(currentTime)
	} else {
		if err := device.BelongsTo(userID); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}

		if err := device.EnsureUsable(); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}

		if err := device.MarkSeen(currentTime); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}

		if err := device.UpdateMetadata(currentTime, &name, &ua, &ip); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}
	}

	if err := uc.deviceRepo.Upsert(device); err != nil {
		return nil, apperr.Internal("storage error updating device", requestID, err)
	}

	return device, nil
}

func (uc *loginUseCase) fetchRoleNames(requestID string, roleIDs []valueobjects.RoleID) ([]string, error) {
	roleNames := make([]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}

func (uc *loginUseCase) issueTokensAndSaveSession(requestID string, tokenID valueobjects.TokenID, user *aggregates.User, device *entities.Device, roles []string, currentTime time.Time) (*dto.AuthResponse, error) {
	accessToken, _, err := uc.tokenService.IssueAccessToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), roles, currentTime,
	)
	if err != nil {
		return nil, apperr.Internal("access token generation failed", requestID, err)
	}

	refreshToken, refreshClaims, err := uc.tokenService.IssueRefreshToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), currentTime,
	)
	if err != nil {
		return nil, apperr.Internal("refresh token generation failed", requestID, err)
	}

	refreshTokenEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), refreshToken, refreshClaims.ExpiresAt, currentTime,
	)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	if err := uc.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), currentTime); err != nil {
		return nil, apperr.Internal("failed to revoke old sessions", requestID, err)
	}

	if err := uc.refreshRepo.Save(refreshTokenEntity); err != nil {
		return nil, apperr.Internal("failed to save new session", requestID, err)
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value(),
		RefreshToken: refreshToken.Value(),
	}, nil
}

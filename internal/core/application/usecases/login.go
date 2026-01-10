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
		logger:         logger,
	}
}

func (uc *loginUseCase) Execute(
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {
	uc.logger.Info("Starting user login", "email", email)
	nowUTC := time.Now().UTC()

	// 1. Authentication
	user, err := uc.authenticate(email, password)
	if err != nil {
		return nil, err
	}

	// 2. Device Identity Management
	device, err := uc.resolveDevice(user.ID(), deviceIDStr, deviceName, userAgent, ipAddress, nowUTC)
	if err != nil {
		return nil, err
	}

	// 3. Authorization Context (Fetch Roles)
	roleNames, err := uc.fetchRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	tokenID, err := uc.uuidGenerator.NewTokenID()
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 4. Token Issuance and Session Persistence
	return uc.issueTokensAndSaveSession(tokenID, user, device, roleNames, nowUTC)
}

// --- Internal Helper Methods ---

func (uc *loginUseCase) authenticate(email, password string) (*aggregates.User, error) {
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	user, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, err
	}
	if user == nil || !uc.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		return nil, apperr.NewUnauthorizedErr("invalid credentials")
	}

	return user, nil
}

func (uc *loginUseCase) resolveDevice(userID valueobjects.UserID, dIDStr, name, ua, ip string, now time.Time) (*entities.Device, error) {
	deviceID, err := uc.uuidParser.ParseDeviceID(dIDStr)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	device, err := uc.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, err
	}

	if device == nil {
		device, err = entities.NewDevice(deviceID, userID, &name, &ua, &ip, true, now)
		if err != nil {
			return nil, apperr.MapDomainErr(err)
		}
	} else {
		device.Update(now, &name, &ua, &ip)
	}

	if err := uc.deviceRepo.Upsert(device); err != nil {
		return nil, apperr.NewInternalErr("failed to save device info")
	}

	return device, nil
}

func (uc *loginUseCase) fetchRoleNames(roleIDs []valueobjects.RoleID) ([]string, error) {
	roleNames := make([]string, 0, len(roleIDs))
	// Optimization: If your repository supports GetByIDs([]RoleID), use it here.
	// Otherwise, this loop is acceptable if the number of roles per user is small.
	for _, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, err
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}

func (uc *loginUseCase) issueTokensAndSaveSession(tokenID valueobjects.TokenID, user *aggregates.User, device *entities.Device, roles []string, nowUTC time.Time) (*dto.AuthResponse, error) {
	// 1. Generate Tokens first (Infrastructure)
	accessToken, _, err := uc.tokenService.IssueAccessToken(tokenID.Value(), user.ID().Value(), device.ID().Value(), roles)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshClaims, err := uc.tokenService.IssueRefreshToken(tokenID.Value(), user.ID().Value(), device.ID().Value())
	if err != nil {
		return nil, err
	}

	refreshTokenEntity, err := entities.NewRefreshToken(
		tokenID,
		user.ID(),
		device.ID(),
		refreshToken.Value(),
		refreshClaims.ExpiresAt,
		nowUTC,
	)
	if err != nil {
		// This will no longer fail because persistenceNow >= refreshClaims.IssuedAt
		return nil, apperr.MapDomainErr(err)
	}

	// 4. Persistence (Infrastructure)
	if err := uc.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), nowUTC); err != nil {
		return nil, err
	}

	if err := uc.refreshRepo.Save(refreshTokenEntity); err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value(),
		RefreshToken: refreshToken.Value(),
	}, nil
}

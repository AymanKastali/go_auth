package usecases

import (
	"errors"
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
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {
	uc.logger.Info("Starting user login", "email", email)
	now := uc.clock.Now().UTC()

	user, err := uc.authenticate(email, password)
	if err != nil {
		return nil, err
	}

	device, err := uc.resolveDevice(user.ID(), deviceIDStr, deviceName, userAgent, ipAddress, now)
	if err != nil {
		return nil, err
	}

	roleNames, err := uc.fetchRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	tokenID, err := uc.uuidGenerator.NewTokenID()
	if err != nil {
		return nil, apperr.Internal(err)
	}

	return uc.issueTokensAndSaveSession(tokenID, user, device, roleNames, now)
}

func (uc *loginUseCase) authenticate(email, password string) (*aggregates.User, error) {
	emailVO := valueobjects.ReconstituteEmail(email)
	user, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	if user == nil {
		return nil, apperr.NotFound(errors.New("user with this email not found"))
	}

	if !uc.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		return nil, apperr.Unauthorized(nil)
	}

	return user, nil
}

func (uc *loginUseCase) resolveDevice(
	userID valueobjects.UserID,
	deviceIDStr, name, ua, ip string,
	now time.Time,
) (*entities.Device, error) {

	deviceID, err := uc.uuidParser.ParseDeviceID(deviceIDStr)
	if err != nil {
		return nil, apperr.Validation(err)
	}

	device, err := uc.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	if device == nil {
		device, err = entities.NewDevice(
			deviceID,
			userID,
			&name,
			&ua,
			&ip,
			now,
		)
		if err != nil {
			return nil, apperr.Validation(err)
		}
		device.Activate(now)
	} else {
		if err := device.BelongsTo(userID); err != nil {
			return nil, apperr.Forbidden(err)
		}

		if err := device.EnsureUsable(); err != nil {
			return nil, apperr.Conflict(err)
		}

		if err := device.MarkSeen(now); err != nil {
			return nil, apperr.Internal(err)
		}

		if err := device.UpdateMetadata(now, &name, &ua, &ip); err != nil {
			return nil, apperr.Internal(err)
		}
	}

	if err := uc.deviceRepo.Upsert(device); err != nil {
		return nil, apperr.Internal(err)
	}

	return device, nil
}

func (uc *loginUseCase) fetchRoleNames(roleIDs []valueobjects.RoleID) ([]string, error) {
	roleNames := make([]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, apperr.Internal(err)
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}

func (uc *loginUseCase) issueTokensAndSaveSession(tokenID valueobjects.TokenID, user *aggregates.User, device *entities.Device, roles []string, now time.Time) (*dto.AuthResponse, error) {
	accessToken, _, err := uc.tokenService.IssueAccessToken(
		tokenID.Value(),
		user.ID().Value(),
		device.ID().Value(),
		roles, uc.clock.NowUTC(),
	)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	refreshToken, refreshClaims, err := uc.tokenService.IssueRefreshToken(
		tokenID.Value(),
		user.ID().Value(),
		device.ID().Value(),
		uc.clock.NowUTC(),
	)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	refreshTokenEntity, err := entities.NewRefreshToken(
		tokenID,
		user.ID(),
		device.ID(),
		refreshToken,
		refreshClaims.ExpiresAt,
		now,
	)
	if err != nil {
		return nil, apperr.Validation(err)
	}

	if err := uc.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), now); err != nil {
		return nil, apperr.Internal(err)
	}

	if err := uc.refreshRepo.Save(refreshTokenEntity); err != nil {
		return nil, apperr.Internal(err)
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value(),
		RefreshToken: refreshToken.Value(),
	}, nil
}

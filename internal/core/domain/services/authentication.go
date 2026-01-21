package services

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type authDomainService struct {
	userRepo       ports.IUserRepository
	deviceRepo     ports.IDeviceRepository
	passwordHasher ports.IPasswordHasherService
	idSvc          ports.IIDService
	deviceFactory  ports.IDeviceFactory
}

func NewAuthDomainService(
	userRepo ports.IUserRepository,
	deviceRepo ports.IDeviceRepository,
	passwordHasher ports.IPasswordHasherService,
	idSvc ports.IIDService,
	deviceFactory ports.IDeviceFactory,
) *authDomainService {
	return &authDomainService{
		userRepo:       userRepo,
		deviceRepo:     deviceRepo,
		passwordHasher: passwordHasher,
		idSvc:          idSvc,
		deviceFactory:  deviceFactory,
	}
}

func (s *authDomainService) Authenticate(emailStr, password string) (*aggregates.User, error) {
	if emailStr == "" {
		return nil, derr.NewErrEmailRequired()
	}
	if password == "" {
		return nil, derr.NewErrPasswordRequired()
	}
	email := valueobjects.ReconstituteEmail(emailStr)

	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil, err // DB errors bubble up to be mapped to Internal
	}
	if user == nil {
		return nil, derr.NewErrInvalidCredentials()
	}

	hashedPwd := user.HashedPassword()
	if err := s.passwordHasher.Compare(password, hashedPwd); err != nil {
		return nil, derr.NewErrPasswordMismatch()
	}

	if !user.IsActive() {
		return nil, derr.NewErrInactiveUser(user.ID().Value())
	}

	return user, nil
}

func (s *authDomainService) ResolveDevice(
	deviceFingerprint valueobjects.DeviceFingerprint,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ip *string,
	now valueobjects.Timepoint,
) (*entities.Device, error) {
	device, err := s.deviceRepo.GetByFingerprint(deviceFingerprint)
	if err != nil {
		return nil, err
	}

	if device == nil {
		device, err = s.deviceFactory.New(deviceFingerprint, userID, name, userAgent, ip, true, now)
		if err != nil {
			return nil, err
		}
	} else {
		if err := device.BelongsTo(userID); err != nil {
			return nil, err
		}
		if err := device.EnsureUsable(); err != nil {
			return nil, err
		}
		err = device.MarkSeen(now)
		if err != nil {
			return nil, err
		}
		err = device.UpdateMetadata(name, userAgent, ip, now)
		if err != nil {
			return nil, err
		}
	}

	if err := s.deviceRepo.Upsert(device); err != nil {
		return nil, err
	}

	return device, nil
}

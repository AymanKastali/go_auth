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
	deviceHasher   ports.IDeviceHasher
}

func NewAuthDomainService(
	userRepo ports.IUserRepository,
	deviceRepo ports.IDeviceRepository,
	passwordHasher ports.IPasswordHasherService,
	idSvc ports.IIDService,
	deviceFactory ports.IDeviceFactory,
	deviceHasher ports.IDeviceHasher,
) *authDomainService {
	return &authDomainService{
		userRepo:       userRepo,
		deviceRepo:     deviceRepo,
		passwordHasher: passwordHasher,
		idSvc:          idSvc,
		deviceFactory:  deviceFactory,
		deviceHasher:   deviceHasher,
	}
}

func (s *authDomainService) Authenticate(emailStr, password string) (*aggregates.User, error) {
	email, err := valueobjects.NewEmail(emailStr)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil, err // DB errors bubble up to be mapped to Internal
	}
	if user == nil {
		return nil, derr.NewErrInvalidCredentials()
	}

	rawPwd, err := valueobjects.NewRawPassword(password)
	if err != nil {
		return nil, derr.NewErrPasswordRequired()
	}
	hashedPwd := user.HashedPassword()
	if err := s.passwordHasher.Compare(rawPwd, hashedPwd); err != nil {
		return nil, derr.NewErrPasswordMismatch()
	}

	if !user.IsActive() {
		return nil, derr.NewErrInactiveUser(user.ID().String())
	}

	return user, nil
}

func (s *authDomainService) DeriveFingerprint(
	traits valueobjects.DeviceFingerprintTraits,
) (valueobjects.DeviceFingerprint, error) {
	return s.deviceHasher.Hash(traits)
}

func (s *authDomainService) ResolveDevice(
	traits valueobjects.DeviceFingerprintTraits,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ip *string,
	now valueobjects.Timepoint,
) (*entities.Device, error) {
	fingerprint, err := s.deviceHasher.Hash(traits)
	if err != nil {
		return nil, err
	}

	device, err := s.deviceRepo.GetByFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	if device == nil {
		device, err = s.deviceFactory.New(fingerprint, userID, name, userAgent, ip, true, now)
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

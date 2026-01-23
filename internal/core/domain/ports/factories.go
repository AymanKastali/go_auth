package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type IUserFactory interface {
	New(
		email valueobjects.Email,
		hashed valueobjects.HashedPassword,
		roles []valueobjects.RoleID,
		now valueobjects.Timepoint,
	) (*aggregates.User, error)
}

type IDeviceFactory interface {
	New(
		deviceFingerprint valueobjects.DeviceFingerprint,
		userID valueobjects.UserID,
		name *string,
		userAgent *string,
		ip *string,
		isActive bool,
		now valueobjects.Timepoint,
	) (*entities.Device, error)
}

type ISessionRenewalTokenFactory interface {
	New(
		userID valueobjects.UserID,
		deviceID valueobjects.DeviceID,
		hashed valueobjects.SessionRenewalHashedToken,
		now valueobjects.Timepoint,
	) (*entities.SessionRenewalToken, error)
}

package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type IUserFactory interface {
	New(
		email valueobjects.Email,
		hashedPassword valueobjects.HashedPassword,
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

type IRefreshTokenFactory interface {
	New(
		userID valueobjects.UserID,
		deviceID valueobjects.DeviceID,
		expiresAt valueobjects.Timepoint,
		now valueobjects.Timepoint,
	) (*entities.RefreshToken, valueobjects.RawRefreshToken, error)
}

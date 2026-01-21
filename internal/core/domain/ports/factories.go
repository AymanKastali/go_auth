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
	) (*aggregates.User, error)
}

type IDeviceFactory interface {
	New(
		deviceFingerprint valueobjects.DeviceFingerprint,
		userID valueobjects.UserID,
		name *string,
		userAgent *string,
		ip *string,
	) (*entities.Device, error)
}

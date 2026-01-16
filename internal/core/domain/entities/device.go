package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type Device struct {
	id         valueobjects.DeviceID
	userID     valueobjects.UserID
	name       *string
	userAgent  *string
	ipAddress  *string
	isActive   bool
	createdAt  time.Time
	updatedAt  time.Time
	lastSeenAt time.Time
	revokedAt  *time.Time
}

func NewDevice(
	deviceID valueobjects.DeviceID,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ipAddress *string,
	currentTime time.Time,
) (*Device, error) {
	if deviceID.IsEmpty() {
		return nil, derr.ErrDeviceIDRequired()
	}
	if userID.IsEmpty() {
		return nil, derr.ErrUserIDRequired()
	}
	if currentTime.IsZero() {
		return nil, derr.ErrCurrentTimeRequired()
	}

	return &Device{
		id:         deviceID,
		userID:     userID,
		name:       name,
		userAgent:  userAgent,
		ipAddress:  ipAddress,
		isActive:   false,
		createdAt:  currentTime,
		updatedAt:  currentTime,
		lastSeenAt: currentTime,
	}, nil
}

func ReconstituteDevice(
	deviceID valueobjects.DeviceID,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ipAddress *string,
	isActive bool,
	createdAt time.Time,
	updatedAt time.Time,
	lastSeenAt time.Time,
	revokedAt *time.Time,
) *Device {
	return &Device{
		id:         deviceID,
		userID:     userID,
		name:       name,
		userAgent:  userAgent,
		ipAddress:  ipAddress,
		isActive:   isActive,
		createdAt:  createdAt,
		updatedAt:  updatedAt,
		lastSeenAt: lastSeenAt,
		revokedAt:  revokedAt,
	}
}

func (e *Device) ID() valueobjects.DeviceID   { return e.id }
func (e *Device) UserID() valueobjects.UserID { return e.userID }
func (e *Device) Name() *string               { return e.name }
func (e *Device) UserAgent() *string          { return e.userAgent }
func (e *Device) IPAddress() *string          { return e.ipAddress }
func (e *Device) IsActive() bool              { return e.isActive }
func (e *Device) CreatedAt() time.Time        { return e.createdAt }
func (e *Device) UpdatedAt() time.Time        { return e.updatedAt }
func (e *Device) LastSeenAt() time.Time       { return e.lastSeenAt }
func (e *Device) RevokedAt() *time.Time       { return e.revokedAt }

func (e *Device) Activate(currentTime time.Time) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}
	if e.isActive {
		return derr.ErrDeviceAlreadyActive(e.id.Value())
	}

	e.isActive = true
	e.touch(currentTime)
	return nil
}

func (e *Device) Deactivate(currentTime time.Time) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}
	if !e.isActive {
		return derr.ErrDeviceAlreadyInactive(e.id.Value())
	}
	e.isActive = false
	e.touch(currentTime)
	return nil
}

func (e *Device) MarkSeen(currentTime time.Time) error {
	if err := e.EnsureUsable(); err != nil {
		return err
	}

	e.lastSeenAt = currentTime
	e.touch(currentTime)
	return nil
}

func (e *Device) UpdateMetadata(
	currentTime time.Time,
	name *string,
	userAgent *string,
	ipAddress *string,
) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}

	e.name = name
	e.userAgent = userAgent
	e.ipAddress = ipAddress

	e.touch(currentTime)
	return nil
}

func (e *Device) Revoke(currentTime time.Time) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}

	e.isActive = false
	e.revokedAt = &currentTime
	e.touch(currentTime)
	return nil
}

func (e *Device) EnsureUsable() error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}
	if !e.isActive {
		return derr.ErrDeviceAlreadyInactive(e.id.Value())
	}
	return nil
}

func (e *Device) BelongsTo(userID valueobjects.UserID) error {
	if !e.userID.Equal(userID) {
		return derr.ErrDeviceDoesNotBelongToUser(e.id.Value(), userID.Value())
	}
	return nil
}

func (e *Device) IsRevoked() bool {
	return e.revokedAt != nil
}

func (e *Device) touch(currentTime time.Time) {
	e.updatedAt = currentTime
}

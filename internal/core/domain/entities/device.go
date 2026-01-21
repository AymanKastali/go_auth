package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
)

type Device struct {
	id          valueobjects.DeviceID
	fingerprint valueobjects.DeviceFingerprint
	userID      valueobjects.UserID
	name        *string
	userAgent   *string
	ipAddress   *string
	isActive    bool
	createdAt   valueobjects.Timepoint
	updatedAt   valueobjects.Timepoint
	lastSeenAt  valueobjects.Timepoint
	revokedAt   *valueobjects.Timepoint
	deletedAt   *valueobjects.Timepoint
}

func NewDevice(
	id valueobjects.DeviceID,
	fingerprint valueobjects.DeviceFingerprint,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ipAddress *string,
	isActive bool,
	now valueobjects.Timepoint,
) (*Device, error) {
	if id.IsEmpty() {
		return nil, derr.ErrDeviceIDRequired()
	}
	if fingerprint.IsEmpty() {
		return nil, derr.ErrDeviceFingerprintRequired()
	}
	if userID.IsEmpty() {
		return nil, derr.ErrUserIDRequired()
	}
	if now.IsZero() {
		return nil, derr.ErrCurrentTimeRequired()
	}

	return &Device{
		id:          id,
		fingerprint: fingerprint,
		userID:      userID,
		name:        name,
		userAgent:   userAgent,
		ipAddress:   ipAddress,
		isActive:    isActive,
		createdAt:   now,
		updatedAt:   now,
		lastSeenAt:  now,
	}, nil
}

func ReconstituteDevice(
	id valueobjects.DeviceID,
	fingerprint valueobjects.DeviceFingerprint,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ipAddress *string,
	isActive bool,
	createdAt valueobjects.Timepoint,
	updatedAt valueobjects.Timepoint,
	lastSeenAt valueobjects.Timepoint,
	revokedAt *valueobjects.Timepoint,
	deletedAt *valueobjects.Timepoint,
) *Device {
	return &Device{
		id:          id,
		fingerprint: fingerprint,
		userID:      userID,
		name:        name,
		userAgent:   userAgent,
		ipAddress:   ipAddress,
		isActive:    isActive,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
		lastSeenAt:  lastSeenAt,
		revokedAt:   revokedAt,
		deletedAt:   deletedAt,
	}
}

func (e *Device) ID() valueobjects.DeviceID                   { return e.id }
func (e *Device) Fingerprint() valueobjects.DeviceFingerprint { return e.fingerprint }
func (e *Device) UserID() valueobjects.UserID                 { return e.userID }
func (e *Device) Name() *string                               { return e.name }
func (e *Device) UserAgent() *string                          { return e.userAgent }
func (e *Device) IPAddress() *string                          { return e.ipAddress }
func (e *Device) IsActive() bool                              { return e.isActive }
func (e *Device) CreatedAt() valueobjects.Timepoint           { return e.createdAt }
func (e *Device) UpdatedAt() valueobjects.Timepoint           { return e.updatedAt }
func (e *Device) LastSeenAt() valueobjects.Timepoint          { return e.lastSeenAt }
func (e *Device) RevokedAt() *valueobjects.Timepoint          { return e.revokedAt }
func (e *Device) DeletedAt() *valueobjects.Timepoint          { return e.revokedAt }

func (e *Device) Activate(now valueobjects.Timepoint) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}
	if e.isActive {
		return derr.ErrDeviceAlreadyActive(e.id.Value())
	}

	e.isActive = true
	e.touch(now)
	return nil
}

func (e *Device) Deactivate(now valueobjects.Timepoint) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}
	if !e.isActive {
		return derr.ErrDeviceAlreadyInactive(e.id.Value())
	}
	e.isActive = false
	e.touch(now)
	return nil
}

func (e *Device) MarkSeen(now valueobjects.Timepoint) error {
	if err := e.EnsureUsable(); err != nil {
		return err
	}

	e.lastSeenAt = now
	e.touch(now)
	return nil
}

func (e *Device) UpdateMetadata(
	name *string,
	userAgent *string,
	ipAddress *string,
	now valueobjects.Timepoint,
) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}

	e.name = name
	e.userAgent = userAgent
	e.ipAddress = ipAddress

	e.touch(now)
	return nil
}

func (e *Device) Revoke(now valueobjects.Timepoint) error {
	if e.IsRevoked() {
		return derr.ErrDeviceRevoked(e.id.Value())
	}

	e.isActive = false
	e.revokedAt = &now
	e.touch(now)
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

func (e *Device) touch(now valueobjects.Timepoint) {
	e.updatedAt = now
}

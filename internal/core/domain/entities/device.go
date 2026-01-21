package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type Device struct {
	id          valueobjects.DeviceID
	fingerprint valueobjects.DeviceFingerprint // Client-provided unique ID
	userID      valueobjects.UserID
	name        *string
	userAgent   *string
	ipAddress   *string
	isActive    bool
	createdAt   time.Time
	updatedAt   time.Time
	lastSeenAt  time.Time
	revokedAt   *time.Time
}

func NewDevice(
	id valueobjects.DeviceID,
	fingerprint valueobjects.DeviceFingerprint,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ipAddress *string,
	isActive bool,
	now time.Time,
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
	createdAt time.Time,
	updatedAt time.Time,
	lastSeenAt time.Time,
	revokedAt *time.Time,
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
	}
}

func (e *Device) ID() valueobjects.DeviceID                   { return e.id }
func (e *Device) Fingerprint() valueobjects.DeviceFingerprint { return e.fingerprint }
func (e *Device) UserID() valueobjects.UserID                 { return e.userID }
func (e *Device) Name() *string                               { return e.name }
func (e *Device) UserAgent() *string                          { return e.userAgent }
func (e *Device) IPAddress() *string                          { return e.ipAddress }
func (e *Device) IsActive() bool                              { return e.isActive }
func (e *Device) CreatedAt() time.Time                        { return e.createdAt }
func (e *Device) UpdatedAt() time.Time                        { return e.updatedAt }
func (e *Device) LastSeenAt() time.Time                       { return e.lastSeenAt }
func (e *Device) RevokedAt() *time.Time                       { return e.revokedAt }

func (e *Device) Activate(now time.Time) error {
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

func (e *Device) Deactivate(now time.Time) error {
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

func (e *Device) MarkSeen(now time.Time) error {
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
	now time.Time,
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

func (e *Device) Revoke(now time.Time) error {
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

func (e *Device) touch(now time.Time) {
	e.updatedAt = now
}

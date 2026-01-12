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
	now time.Time,
) (*Device, error) {
	if deviceID.IsEmpty() {
		return nil, derr.NewValidation.RequiredDeviceID()
	}
	if userID.IsEmpty() {
		return nil, derr.NewValidation.RequiredUserID()
	}
	if now.IsZero() {
		return nil, derr.NewValidation.RequiredNow()
	}

	return &Device{
		id:         deviceID,
		userID:     userID,
		name:       name,
		userAgent:  userAgent,
		ipAddress:  ipAddress,
		isActive:   true,
		createdAt:  now,
		updatedAt:  now,
		lastSeenAt: now,
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

func (e *Device) Activate(now time.Time) error {
	if e.IsRevoked() {
		return derr.NewViolation.DeviceRevoked()
	}
	if e.isActive {
		return derr.NewViolation.DeviceAlreadyActive()
	}

	e.isActive = true
	e.touch(now)
	return nil
}

func (e *Device) Deactivate(now time.Time) error {
	if e.IsRevoked() {
		return derr.NewViolation.DeviceRevoked()
	}
	if !e.isActive {
		return derr.NewViolation.DeviceAlreadyInactive()
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
	now time.Time,
	name *string,
	userAgent *string,
	ipAddress *string,
) error {
	if e.IsRevoked() {
		return derr.NewViolation.DeviceRevoked()
	}

	e.name = name
	e.userAgent = userAgent
	e.ipAddress = ipAddress

	e.touch(now)
	return nil
}

func (e *Device) Revoke(now time.Time) error {
	if e.IsRevoked() {
		return derr.NewViolation.DeviceRevoked()
	}

	e.isActive = false
	e.revokedAt = &now
	e.touch(now)
	return nil
}

func (e *Device) EnsureUsable() error {
	if e.IsRevoked() {
		return derr.NewViolation.DeviceRevoked()
	}
	if !e.isActive {
		return derr.NewViolation.DeviceAlreadyInactive()
	}
	return nil
}

func (e *Device) BelongsTo(userID valueobjects.UserID) error {
	if !e.userID.Equal(userID) {
		return derr.NewViolation.DeviceDoesNotBelongToUser()
	}
	return nil
}

func (e *Device) IsRevoked() bool {
	return e.revokedAt != nil
}

func (e *Device) touch(now time.Time) {
	e.updatedAt = now
}

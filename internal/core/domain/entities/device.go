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
		return nil, derr.NewRequiredErr("device_id")
	}
	if userID.IsEmpty() {
		return nil, derr.NewRequiredErr("user_id")
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
) (*Device, error) {

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
	}, nil
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
	if e.revokedAt != nil {
		return derr.NewRuleViolationErr("cannot activate a revoked device")
	}
	if e.isActive {
		return derr.NewRuleViolationErr("device is already active")
	}

	e.isActive = true
	e.touch(now)
	return nil
}

func (e *Device) Deactivate(now time.Time) error {
	if e.revokedAt != nil {
		return derr.NewRuleViolationErr("cannot deactivate a revoked device")
	}
	if !e.isActive {
		return derr.NewRuleViolationErr("device is already inactive")
	}

	e.isActive = false
	e.touch(now)
	return nil
}

func (e *Device) MarkSeen(now time.Time) error {
	if e.revokedAt != nil {
		return derr.NewRuleViolationErr("cannot use a revoked device")
	}
	if !e.isActive {
		return derr.NewRuleViolationErr("cannot use an inactive device")
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
	if e.revokedAt != nil {
		return derr.NewRuleViolationErr("cannot update a revoked device")
	}

	if name != nil {
		e.name = name
	}
	if userAgent != nil {
		e.userAgent = userAgent
	}
	if ipAddress != nil {
		e.ipAddress = ipAddress
	}

	e.touch(now)
	return nil
}

func (e *Device) Revoke(now time.Time) error {
	if e.revokedAt != nil {
		return derr.NewRuleViolationErr("device is already revoked")
	}

	e.isActive = false
	e.revokedAt = &now
	e.touch(now)
	return nil
}

func (e *Device) EnsureUsable() error {
	if e.revokedAt != nil {
		return derr.NewRuleViolationErr("device is revoked")
	}
	if !e.isActive {
		return derr.NewRuleViolationErr("device is inactive")
	}
	return nil
}

func (e *Device) BelongsTo(userID valueobjects.UserID) error {
	if !e.userID.Equal(userID) {
		return derr.NewInvalidValueErr("UserID")
	}
	return nil
}

func (e *Device) touch(now time.Time) {
	e.updatedAt = now
}

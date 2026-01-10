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
	isActive bool,
	nowUTC time.Time,
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
		createdAt:  nowUTC,
		updatedAt:  nowUTC,
		lastSeenAt: nowUTC,
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

func (d *Device) ID() valueobjects.DeviceID   { return d.id }
func (d *Device) UserID() valueobjects.UserID { return d.userID }
func (d *Device) Name() *string               { return d.name }
func (d *Device) UserAgent() *string          { return d.userAgent }
func (d *Device) IPAddress() *string          { return d.ipAddress }
func (d *Device) IsActive() bool              { return d.isActive }
func (d *Device) CreatedAt() time.Time        { return d.createdAt }
func (d *Device) UpdatedAt() time.Time        { return d.updatedAt }
func (d *Device) LastSeenAt() time.Time       { return d.lastSeenAt }
func (d *Device) RevokedAt() *time.Time       { return d.revokedAt }

func (d *Device) Update(
	now time.Time,
	name *string,
	userAgent *string,
	ipAddress *string,
) error {

	if d.revokedAt != nil {
		return derr.NewRuleViolationErr("cannot update a revoked device")
	}

	if name != nil {
		d.name = name
	}
	if userAgent != nil {
		d.userAgent = userAgent
	}
	if ipAddress != nil {
		d.ipAddress = ipAddress
	}

	d.lastSeenAt = now
	d.updatedAt = now
	return nil
}

func (d *Device) Revoke(now time.Time) error {
	if d.revokedAt != nil {
		return derr.NewRuleViolationErr("device is already revoked")
	}

	d.isActive = false
	d.revokedAt = &now
	d.updatedAt = now
	return nil
}

func (d *Device) EnsureUsable() error {
	if d.revokedAt != nil {
		return derr.NewRuleViolationErr("device is revoked")
	}
	if !d.isActive {
		return derr.NewRuleViolationErr("device is inactive")
	}
	return nil
}

func (d *Device) BelongsTo(userID valueobjects.UserID) error {
	if !d.userID.Equal(userID) {
		// If it's the wrong user, it's a violation of access/value logic
		return derr.NewInvalidValueErr("UserID")
	}
	return nil
}

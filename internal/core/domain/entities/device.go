package entities

import (
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

const (
	newDeviceOp           = "Device.New"
	reconstituteDeviceOp  = "Device.Reconstitute"
	updateDeviceOp        = "Device.Update"
	revokeDeviceOp        = "Device.Revoke"
	ensureDeviceUsableOp  = "Device.EnsureUsable"
	validateDeviceOwnerOp = "Device.ValidateOwner"
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
	var missing []string

	if deviceID.IsZero() {
		missing = append(missing, "id")
	}
	if userID.IsZero() {
		missing = append(missing, "user_id")
	}
	if len(missing) > 0 {
		return nil, domainerr.RequiredAttrsError(
			missing,
			createRefreshTokenOp,
		)
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
		return domainerr.OperationDeniedError(
			"revoked device cannot be updated",
			updateDeviceOp,
		)
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
		return domainerr.InvalidStateError(
			"device already revoked",
			revokeDeviceOp,
		)
	}

	d.isActive = false
	d.revokedAt = &now
	d.updatedAt = now
	return nil
}

func (d *Device) EnsureUsable() error {
	if d.revokedAt != nil {
		return domainerr.InvalidStateError(
			"device is revoked",
			ensureDeviceUsableOp,
		)
	}
	if !d.isActive {
		return domainerr.InvalidStateError(
			"device is inactive",
			ensureDeviceUsableOp,
		)
	}
	return nil
}

func (d *Device) BelongsTo(userID valueobjects.UserID) error {
	if !d.userID.Equal(userID) {
		return domainerr.OperationDeniedError(
			"device does not belong to user",
			validateDeviceOwnerOp,
		)
	}
	return nil
}

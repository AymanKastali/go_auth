package entities

import (
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

const newDeviceOp = "Device.New"
const reconstituteDeviceOp = "Device.ReconstituteDevice"

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

// Constructor
func NewDevice(
	deviceID valueobjects.DeviceID,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ipAddress *string,
	isActive bool,
	nowUTC time.Time,
) (*Device, error) {
	if deviceID.IsZero() {
		return nil, domainerr.NewDomainRequiredAttrError("device id", newDeviceOp)
	}
	if userID.IsZero() {
		return nil, domainerr.NewDomainRequiredAttrError("user id", newDeviceOp)
	}

	d := &Device{
		id:        deviceID,
		userID:    userID,
		isActive:  isActive,
		createdAt: nowUTC,
		updatedAt: nowUTC,
	}

	// Use private setters for optional fields
	d.setName(name)
	d.setUserAgent(userAgent)
	d.setIPAddress(ipAddress)
	d.setLastSeen(nowUTC)

	return d, nil
}

// ReconstituteDevice creates a Device from persistence (DB) — no setters needed
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
	if deviceID.IsZero() {
		return nil, domainerr.NewDomainRequiredAttrError("device id", reconstituteDeviceOp)
	}
	if userID.IsZero() {
		return nil, domainerr.NewDomainRequiredAttrError("user id", reconstituteDeviceOp)
	}

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

// --- Getters ---
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

// --- Methods ---
func (e *Device) touch() {
	e.updatedAt = time.Now().UTC()
}

func (e *Device) UpdateLastSeen(now time.Time) {
	e.setLastSeen(now)
}

func (e *Device) Revoke(now time.Time) {
	e.setActive(false)
	e.setRevokedAt(&now)
}

func (e *Device) EnsureActive() error {
	if !e.isActive {
		return domainerr.ErrDeviceInactive
	}
	return nil
}

func (e *Device) EnsureNotRevoked() error {
	if e.revokedAt != nil {
		return domainerr.ErrDeviceRevoked
	}
	return nil
}

func (e *Device) EnsureUsable() error {
	if err := e.EnsureNotRevoked(); err != nil {
		return err
	}
	if err := e.EnsureActive(); err != nil {
		return err
	}
	return nil
}

func (e *Device) BelongsTo(userID valueobjects.UserID) error {
	if !e.userID.Equal(userID) {
		return domainerr.ErrInvalidDeviceUser
	}
	return nil
}

// --- Private setters (fluent) ---
func (e *Device) setName(name *string) *Device {
	e.name = name
	e.touch()
	return e
}

func (e *Device) setUserAgent(agent *string) *Device {
	e.userAgent = agent
	e.touch()
	return e
}

func (e *Device) setIPAddress(ip *string) *Device {
	e.ipAddress = ip
	e.touch()
	return e
}

func (e *Device) setActive(active bool) *Device {
	e.isActive = active
	e.touch()
	return e
}

func (e *Device) setRevokedAt(t *time.Time) *Device {
	e.revokedAt = t
	e.touch()
	return e
}

func (e *Device) setLastSeen(t time.Time) *Device {
	e.lastSeenAt = t
	e.touch()
	return e
}

// --- Public update method ---
func (e *Device) Update(lastSeen time.Time, name, userAgent, ip *string) *Device {
	if name != nil {
		e.setName(name)
	}
	if userAgent != nil {
		e.setUserAgent(userAgent)
	}
	if ip != nil {
		e.setIPAddress(ip)
	}
	return e
}

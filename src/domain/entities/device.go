package entities

import (
	"go_auth/src/domain/errors"
	"go_auth/src/domain/value_objects"
	"time"
)

type Device struct {
	ID         value_objects.DeviceId
	UserId     value_objects.UserId
	Name       *string
	UserAgent  *string
	IPAddress  *string
	IsActive   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastSeenAt *time.Time
	RevokedAt  *time.Time
}

func (e *Device) touch() {
	e.UpdatedAt = time.Now().UTC()
}

func (e *Device) UpdateLastSeen(now time.Time) {
	e.LastSeenAt = &now
}

func (e *Device) IsRevoked() bool {
	return e.RevokedAt != nil
}

func (e *Device) IsActiveCheck() bool {
	return e.IsActive
}

func (e *Device) EnsureActive() error {
	if !e.IsActiveCheck() {
		return errors.ErrDeviceInactive
	}
	return nil
}

func (e *Device) EnsureNotRevoked() error {
	if e.IsRevoked() {
		return errors.ErrDeviceRevoked
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

func (e *Device) Revoke(now time.Time) {
	e.IsActive = false
	e.RevokedAt = &now
}

func (e *Device) BelongsTo(userId value_objects.UserId) error {
	if e.UserId != userId {
		return errors.ErrInvalidDeviceUser
	}
	return nil
}

package entities

import (
	"go_auth/internal/domain/domainerr"
	"go_auth/internal/domain/valueobjects"
	"time"
)

type Device struct {
	ID         valueobjects.DeviceID
	UserID     valueobjects.UserID
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
		return domainerr.ErrDeviceInactive
	}
	return nil
}

func (e *Device) EnsureNotRevoked() error {
	if e.IsRevoked() {
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

func (e *Device) Revoke(now time.Time) {
	e.IsActive = false
	e.RevokedAt = &now
}

func (e *Device) BelongsTo(userID valueobjects.UserID) error {
	if e.UserID != userID {
		return domainerr.ErrInvalidDeviceUser
	}
	return nil
}

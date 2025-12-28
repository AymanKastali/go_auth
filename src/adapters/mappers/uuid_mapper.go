package mappers

import (
	"fmt"
	"go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type UUIDMapper struct{}

func NewUUIDMapper() *UUIDMapper {
	return &UUIDMapper{}
}

// ---------------- UserID ----------------

func (m *UUIDMapper) UserIdFromString(s string) (value_objects.UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.UserID{}, fmt.Errorf("invalid UserID UUID string: %w", err)
	}
	return value_objects.UserID{Value: id}, nil
}

func (m *UUIDMapper) UserIdToString(vo value_objects.UserID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) UserIdFromUUID(u uuid.UUID) value_objects.UserID {
	return value_objects.UserID{Value: u}
}

// ---------------- DeviceID ----------------

func (m *UUIDMapper) DeviceIdFromString(s string) (value_objects.DeviceID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.DeviceID{}, fmt.Errorf("invalid DeviceID UUID string: %w", err)
	}
	return value_objects.DeviceID{Value: id}, nil
}

func (m *UUIDMapper) DeviceIdToString(vo value_objects.DeviceID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) DeviceIdFromUUID(u uuid.UUID) value_objects.DeviceID {
	return value_objects.DeviceID{Value: u}
}

// ---------------- TokenID ----------------

func (m *UUIDMapper) TokenIdFromString(s string) (value_objects.TokenID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.TokenID{}, fmt.Errorf("invalid TokenID UUID string: %w", err)
	}
	return value_objects.TokenID{Value: id}, nil
}

func (m *UUIDMapper) TokenIdToString(vo value_objects.TokenID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) TokenIdFromUUID(u uuid.UUID) value_objects.TokenID {
	return value_objects.TokenID{Value: u}
}

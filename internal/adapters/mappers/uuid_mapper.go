package mappers

import (
	"fmt"
	"go_auth/internal/domain/valueobjects"

	"github.com/google/uuid"
)

type UUIDMapper struct{}

func NewUUIDMapper() *UUIDMapper {
	return &UUIDMapper{}
}

// ---------------- UserID ----------------

func (m *UUIDMapper) UserIdFromString(s string) (valueobjects.UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return valueobjects.UserID{}, fmt.Errorf("invalid UserID UUID string: %w", err)
	}
	return valueobjects.UserID{Value: id}, nil
}

func (m *UUIDMapper) UserIdToString(vo valueobjects.UserID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) UserIdFromUUID(u uuid.UUID) valueobjects.UserID {
	return valueobjects.UserID{Value: u}
}

// ---------------- DeviceID ----------------

func (m *UUIDMapper) DeviceIdFromString(s string) (valueobjects.DeviceID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return valueobjects.DeviceID{}, fmt.Errorf("invalid DeviceID UUID string: %w", err)
	}
	return valueobjects.DeviceID{Value: id}, nil
}

func (m *UUIDMapper) DeviceIdToString(vo valueobjects.DeviceID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) DeviceIdFromUUID(u uuid.UUID) valueobjects.DeviceID {
	return valueobjects.DeviceID{Value: u}
}

// ---------------- TokenID ----------------

func (m *UUIDMapper) TokenIdFromString(s string) (valueobjects.TokenID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return valueobjects.TokenID{}, fmt.Errorf("invalid TokenID UUID string: %w", err)
	}
	return valueobjects.TokenID{Value: id}, nil
}

func (m *UUIDMapper) TokenIdToString(vo valueobjects.TokenID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) TokenIdFromUUID(u uuid.UUID) valueobjects.TokenID {
	return valueobjects.TokenID{Value: u}
}

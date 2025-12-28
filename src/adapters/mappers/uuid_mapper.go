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

// ---------------- UserId ----------------

func (m *UUIDMapper) UserIdFromString(s string) (value_objects.UserId, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.UserId{}, fmt.Errorf("invalid UserId UUID string: %w", err)
	}
	return value_objects.UserId{Value: id}, nil
}

func (m *UUIDMapper) UserIdToString(vo value_objects.UserId) string {
	return vo.Value.String()
}

func (m *UUIDMapper) UserIdFromUUID(u uuid.UUID) value_objects.UserId {
	return value_objects.UserId{Value: u}
}

// ---------------- DeviceId ----------------

func (m *UUIDMapper) DeviceIdFromString(s string) (value_objects.DeviceId, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.DeviceId{}, fmt.Errorf("invalid DeviceId UUID string: %w", err)
	}
	return value_objects.DeviceId{Value: id}, nil
}

func (m *UUIDMapper) DeviceIdToString(vo value_objects.DeviceId) string {
	return vo.Value.String()
}

func (m *UUIDMapper) DeviceIdFromUUID(u uuid.UUID) value_objects.DeviceId {
	return value_objects.DeviceId{Value: u}
}

// ---------------- TokenId ----------------

func (m *UUIDMapper) TokenIdFromString(s string) (value_objects.TokenId, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.TokenId{}, fmt.Errorf("invalid TokenId UUID string: %w", err)
	}
	return value_objects.TokenId{Value: id}, nil
}

func (m *UUIDMapper) TokenIdToString(vo value_objects.TokenId) string {
	return vo.Value.String()
}

func (m *UUIDMapper) TokenIdFromUUID(u uuid.UUID) value_objects.TokenId {
	return value_objects.TokenId{Value: u}
}

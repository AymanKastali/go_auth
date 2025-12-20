package mappers

import (
	"fmt"
	value_objects "go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type UUIDMapper struct{}

func NewUUIDMapper() *UUIDMapper {
	return &UUIDMapper{}
}

func (m *UUIDMapper) FromString(s string) (value_objects.UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.UserID{}, fmt.Errorf("invalid UUID string: %w", err)
	}
	return value_objects.UserID{Value: id}, nil
}

func (m *UUIDMapper) ToString(vo value_objects.UserID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) FromUUID(u uuid.UUID) value_objects.UserID {
	return value_objects.UserID{Value: u}
}

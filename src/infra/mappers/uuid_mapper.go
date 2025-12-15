package mappers

import (
	"fmt"

	valueobjects "go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type UUIDMapper struct{}

func NewUUIDMapper() *UUIDMapper {
	return &UUIDMapper{}
}

func (m *UUIDMapper) FromString(s string) (valueobjects.UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return valueobjects.UserID{}, fmt.Errorf("invalid UUID string: %w", err)
	}
	return valueobjects.UserID{Value: id}, nil
}

func (m *UUIDMapper) ToString(vo valueobjects.UserID) string {
	return vo.Value.String()
}

func (m *UUIDMapper) FromUUID(u uuid.UUID) valueobjects.UserID {
	return valueobjects.UserID{Value: u}
}

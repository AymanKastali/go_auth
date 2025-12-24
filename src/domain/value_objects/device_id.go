package value_objects

import "github.com/google/uuid"

type DeviceId struct {
	Value uuid.UUID
}

func (id DeviceId) IsZero() bool {
	return id.Value == uuid.Nil
}

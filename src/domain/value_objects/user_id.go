package value_objects

import "github.com/google/uuid"

type UserId struct {
	Value uuid.UUID
}

func (id UserId) IsZero() bool {
	return id.Value == uuid.Nil
}

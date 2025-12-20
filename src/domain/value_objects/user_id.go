package value_objects

import "github.com/google/uuid"

type UserID struct {
	Value uuid.UUID
}

func (id UserID) IsZero() bool {
	return id.Value == uuid.Nil
}

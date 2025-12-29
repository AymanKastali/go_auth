package valueobjects

import "github.com/google/uuid"

type TokenID struct {
	Value uuid.UUID
}

func (id TokenID) IsZero() bool {
	return id.Value == uuid.Nil
}

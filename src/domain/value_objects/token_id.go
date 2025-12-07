package valueobjects

import "github.com/google/uuid"

type TokenID struct {
	value uuid.UUID
}

func NewTokenID() TokenID {
	return TokenID{value: uuid.New()}
}

func (t TokenID) Value() uuid.UUID {
	return t.value
}

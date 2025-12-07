package valueobjects

import "github.com/google/uuid"

type UserID struct {
	value uuid.UUID
}

func NewUserID() UserID {
	return UserID{value: uuid.New()}
}

func UserIDFromUUID(value uuid.UUID) UserID {
	return UserID{value: value}
}

func UserIDFromString(s string) (UserID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return UserID{}, err
	}
	return UserID{value: u}, nil
}

func (id UserID) Value() uuid.UUID {
	return id.value
}

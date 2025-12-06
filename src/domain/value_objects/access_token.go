package valueobjects

import (
	"time"

	"github.com/google/uuid"
)

type AccessToken struct {
	JTI       uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
}

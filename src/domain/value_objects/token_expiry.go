package valueobjects

import "time"

type TokenExpiry struct {
	Value time.Time
}

func (t TokenExpiry) IsExpired() bool {
	return time.Time(t.Value).Before(time.Now())
}

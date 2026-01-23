package dto

import "time"

type AuthUser struct {
	ID        string
	Email     string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	Roles     []string
}

package request

import "github.com/google/uuid"

type LoginRequest struct {
	Email          string     `json:"email" validate:"required,email"`
	Password       string     `json:"password" validate:"required,min=8"`
	OrganizationID *uuid.UUID `json:"organization_id" validate:"omitempty"`
}

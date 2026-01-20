package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type IUserFactory interface {
	CreateNewUser(
		email valueobjects.Email,
		hashedPassword valueobjects.HashedPassword,
	) (*aggregates.User, error)
}

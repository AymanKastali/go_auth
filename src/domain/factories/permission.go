package factories

import (
	"errors"
	"go_auth/src/domain/entities"
	"time"
)

type PermissionFactory struct{}

func (f *PermissionFactory) New(
	key string,
	name string,
	category string,
) (*entities.Permission, error) {
	if key == "" {
		return nil, errors.New("permission key cannot be empty")
	}

	// 2. Create the Entity
	now := time.Now().UTC()
	idFactory := IDFactory{}

	return &entities.Permission{
		ID:        idFactory.NewPermissionID(),
		Key:       key,
		Name:      name,
		Category:  category,
		CreatedAt: now,
	}, nil
}

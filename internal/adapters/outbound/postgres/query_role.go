package postgres

import (
	"context"
	"errors"
	"fmt"

	"go_auth/internal/application"
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

type postgresRoleQueryAdapter struct {
	db *gorm.DB
}

func NewPostgresRoleQueryAdapter(db *gorm.DB) application.IRoleQueryPort {
	return &postgresRoleQueryAdapter{db: db}
}

func (q *postgresRoleQueryAdapter) FindByID(ctx context.Context, id string) (application.RoleReadModel, error) {
	var model RoleModel
	err := getDB(q.db, ctx).
		Preload("Permissions").
		Where("ulid = ?", id).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return application.ZeroRoleReadModel, application.ErrResourceNotFound
		}
		return application.ZeroRoleReadModel, domain.ErrInternal
	}

	return toRoleReadModel(model), nil
}

func (q *postgresRoleQueryAdapter) FindAll(ctx context.Context) ([]application.RoleReadModel, error) {
	var models []RoleModel

	if err := getDB(q.db, ctx).Preload("Permissions").Find(&models).Error; err != nil {
		return nil, domain.ErrInternal
	}

	result := make([]application.RoleReadModel, len(models))
	for i, m := range models {
		result[i] = toRoleReadModel(m)
	}

	return result, nil
}

func toRoleReadModel(m RoleModel) application.RoleReadModel {
	permissions := make([]string, len(m.Permissions))
	for i, p := range m.Permissions {
		permissions[i] = fmt.Sprintf("%s:%s", p.Resource, p.Action)
	}

	return application.RoleReadModel{
		ID:          m.ULID,
		Name:        m.Name,
		Description: m.Description,
		Permissions: permissions,
	}
}

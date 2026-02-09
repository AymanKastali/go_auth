package postgres

import (
	"context"
	"errors"

	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
)

type postgresUserQueryAdapter struct {
	db *gorm.DB
}

func NewPostgresUserQueryAdapter(db *gorm.DB) application.IUserQueryPort {
	return &postgresUserQueryAdapter{db: db}
}

func (q *postgresUserQueryAdapter) FindByID(ctx context.Context, id string) (application.UserReadModel, error) {
	var model UserModel
	err := getDB(q.db, ctx).
		Preload("UserRoles").
		Where("id = ?", id).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return application.ZeroUserReadModel, application.ErrResourceNotFound
		}
		return application.ZeroUserReadModel, domain.ErrInternal
	}

	return toUserReadModel(model), nil
}

func (q *postgresUserQueryAdapter) FindByEmail(ctx context.Context, email string) (application.UserReadModel, error) {
	var model UserModel
	err := getDB(q.db, ctx).
		Preload("UserRoles").
		Where("email = ?", email).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return application.ZeroUserReadModel, application.ErrResourceNotFound
		}
		return application.ZeroUserReadModel, domain.ErrInternal
	}

	return toUserReadModel(model), nil
}

func toUserReadModel(m UserModel) application.UserReadModel {
	roles := make([]string, len(m.UserRoles))
	for i, ur := range m.UserRoles {
		roles[i] = ur.RoleName
	}

	return application.UserReadModel{
		ID:           m.ID,
		Email:        m.Email,
		IsActive:     m.IsActive,
		Roles:        roles,
		RegisteredAt: m.RegisteredAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

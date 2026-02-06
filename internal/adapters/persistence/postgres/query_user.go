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
	return application.UserReadModel{
		ID:        m.ID,
		Email:     m.Email,
		IsActive:  m.IsActive,
		Roles:     m.Roles,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

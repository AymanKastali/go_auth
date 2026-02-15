package postgres

import (
	"context"
	"errors"

	"go_auth/internal/application"
	"go_auth/internal/domain"

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
		Where("ulid = ?", id).
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

func (q *postgresUserQueryAdapter) FindAll(ctx context.Context, offset, limit int) ([]application.UserReadModel, int64, error) {
	var models []UserModel
	var total int64

	db := getDB(q.db, ctx)

	if err := db.Model(&UserModel{}).Count(&total).Error; err != nil {
		return nil, 0, domain.ErrInternal
	}

	if err := db.Preload("UserRoles").Offset(offset).Limit(limit).Find(&models).Error; err != nil {
		return nil, 0, domain.ErrInternal
	}

	result := make([]application.UserReadModel, len(models))
	for i, m := range models {
		result[i] = toUserReadModel(m)
	}

	return result, total, nil
}

func toUserReadModel(m UserModel) application.UserReadModel {
	roles := make([]string, len(m.UserRoles))
	for i, ur := range m.UserRoles {
		roles[i] = ur.RoleName
	}

	return application.UserReadModel{
		ID:           m.ULID,
		Email:        m.Email,
		IsActive:     m.IsActive,
		Roles:        roles,
		RegisteredAt: m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

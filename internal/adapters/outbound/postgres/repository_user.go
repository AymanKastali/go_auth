package postgres

import (
	"context"
	"errors"
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

type postgresUserRepository struct {
	db *gorm.DB
}

func NewPostgresUserRepository(db *gorm.DB) domain.IUserRepository {
	return &postgresUserRepository{db: db}
}

func (r *postgresUserRepository) Save(ctx context.Context, user *domain.User) error {
	model := toUserModel(user)
	db := getDB(r.db, ctx)

	// Resolve own PK (0 = new record)
	pk, err := resolvePK(db, &UserModel{}, model.ULID)
	if err != nil {
		return err
	}
	model.ID = pk

	// Save the user record itself (omit associations to avoid FK ordering issues)
	if err := db.Omit("UserRoles").Save(&model).Error; err != nil {
		return domain.ErrInternal
	}

	// Replace user_roles: delete existing, insert current with the resolved PK
	if err := db.Where("user_id = ?", model.ID).Delete(&UserRoleModel{}).Error; err != nil {
		return domain.ErrInternal
	}
	if len(model.UserRoles) > 0 {
		for i := range model.UserRoles {
			model.UserRoles[i].UserID = model.ID
		}
		if err := db.Create(&model.UserRoles).Error; err != nil {
			return domain.ErrInternal
		}
	}

	return nil
}

func (r *postgresUserRepository) FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	var model UserModel
	err := getDB(r.db, ctx).
		Preload("UserRoles").
		Where("email = ?", email.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toUserDomain(model)
}

func (r *postgresUserRepository) FindByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	var model UserModel
	err := getDB(r.db, ctx).
		Preload("UserRoles").
		Where("ulid = ?", id.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toUserDomain(model)
}

func (r *postgresUserRepository) FindAll(ctx context.Context, offset, limit int) ([]*domain.User, error) {
	var models []UserModel
	err := getDB(r.db, ctx).
		Preload("UserRoles").
		Offset(offset).
		Limit(limit).
		Find(&models).Error

	if err != nil {
		return nil, domain.ErrInternal
	}

	users := make([]*domain.User, 0, len(models))
	for _, m := range models {
		u, err := toUserDomain(m)
		if err != nil {
			return nil, domain.ErrInternal
		}
		users = append(users, u)
	}
	return users, nil
}

func (r *postgresUserRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := getDB(r.db, ctx).Model(&UserModel{}).Count(&count).Error
	if err != nil {
		return 0, domain.ErrInternal
	}
	return count, nil
}

func (r *postgresUserRepository) Delete(ctx context.Context, id domain.UserID) error {
	err := getDB(r.db, ctx).
		Unscoped().
		Where("ulid = ?", id.String()).
		Delete(&UserModel{}).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}

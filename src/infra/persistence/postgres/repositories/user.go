package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserPostgresRepository struct {
	db *gorm.DB
}

func NewUserPostgresRepository(db *gorm.DB) repositories.UserRepository {
	return &UserPostgresRepository{db: db}
}

func (r *UserPostgresRepository) Save(user *entities.User) error {
	model := models.UserModel{
		ID:           user.ID,
		Email:        user.Email.Value(),
		PasswordHash: user.PasswordHash.Value(),
		IsActive:     user.IsActive,
	}

	return r.db.Create(&model).Error
}

func (r *UserPostgresRepository) GetByEmail(
	email valueobjects.Email,
) (*entities.User, error) {

	var model models.UserModel

	err := r.db.
		Where("email = ?", email.Value()).
		First(&model).
		Error

	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.toDomain(model)
}

func (r *UserPostgresRepository) GetByID(
	id uuid.UUID,
) (*entities.User, error) {

	var model models.UserModel

	err := r.db.
		Where("id = ?", id).
		First(&model).
		Error

	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.toDomain(model)
}

func (r *UserPostgresRepository) toDomain(
	model models.UserModel,
) (*entities.User, error) {

	email, err := valueobjects.NewEmail(model.Email)
	if err != nil {
		return nil, err
	}

	return &entities.User{
		ID:           model.ID,
		Email:        email,
		PasswordHash: valueobjects.NewPasswordHash(model.PasswordHash),
		IsActive:     model.IsActive,
	}, nil
}

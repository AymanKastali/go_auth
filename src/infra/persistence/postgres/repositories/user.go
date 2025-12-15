package repositories

import (
	"errors"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres/models"

	"gorm.io/gorm"
)

type GormUserRepository struct {
	DB     *gorm.DB
	Mapper mappers.UserMapper
}

var _ repositories.UserRepositoryPort = (*GormUserRepository)(nil)

func NewGormUserRepository(
	db *gorm.DB,
	mapper mappers.UserMapper,
) repositories.UserRepositoryPort {
	return &GormUserRepository{
		DB:     db,
		Mapper: mapper,
	}
}

func (r *GormUserRepository) Save(u *entities.User) error {

	model, err := r.Mapper.ToModel(u)
	if err != nil {
		return err
	}

	result := r.DB.
		Session(&gorm.Session{FullSaveAssociations: true}).
		Save(model)

	return result.Error
}

func (r *GormUserRepository) GetByEmail(
	email valueobjects.Email,
) (*entities.User, error) {

	var model models.User

	err := r.DB.
		Where("email = ?", email.Value).
		First(&model).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.Mapper.ToDomain(&model)
}

func (r *GormUserRepository) GetByID(
	id valueobjects.UserID,
) (*entities.User, error) {

	var model models.User

	modelID := id.Value.String()

	err := r.DB.
		Where("id = ?", modelID).
		First(&model).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.Mapper.ToDomain(&model)
}

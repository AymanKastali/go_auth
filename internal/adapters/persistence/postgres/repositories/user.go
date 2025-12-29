package repositories

import (
	"errors"
	"fmt"
	"go_auth/internal/adapters/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/domain/entities"
	"go_auth/internal/domain/ports/repositories"
	"go_auth/internal/domain/valueobjects"

	"gorm.io/gorm"
)

type GormUserRepository struct {
	db     *gorm.DB
	mapper *mappers.UserMapper
}

var _ repositories.UserRepositoryPort = (*GormUserRepository)(nil)

func NewGormUserRepository(
	db *gorm.DB,
	mapper *mappers.UserMapper,
) repositories.UserRepositoryPort {
	return &GormUserRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormUserRepository) Save(u *entities.User) error {

	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err
	}

	result := r.db.
		Session(&gorm.Session{FullSaveAssociations: true}).
		Save(model)

	return result.Error
}

func (r *GormUserRepository) GetByEmail(
	email valueobjects.Email,
) (*entities.User, error) {

	var model models.User

	err := r.db.
		Where("email = ?", email.Value).
		First(&model).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) GetByID(
	id valueobjects.UserID,
) (*entities.User, error) {

	var model models.User

	modelID := id.Value.String()

	err := r.db.
		Where("id = ?", modelID).
		First(&model).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) Update(u *entities.User) error {
	// 1. Map Domain Entity to DB Model using your Mapper
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return fmt.Errorf("repository update: mapping failed: %w", err)
	}

	// 2. Perform the update
	// Using a map ensures 'Roles' is updated even if the slice is empty
	result := r.db.Model(&models.User{}).
		Where("id = ?", model.ID).
		Updates(map[string]any{
			"email":         model.Email,
			"password_hash": model.PasswordHash,
			"status":        model.Status,
			"roles":         model.Roles, // datatypes.JSONSlice handles the valuer interface
			"updated_at":    u.UpdatedAt, // Use the entity's timestamp
		})

	if result.Error != nil {
		return fmt.Errorf("repository update: database error: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.New("repository update: user not found")
	}

	return nil
}

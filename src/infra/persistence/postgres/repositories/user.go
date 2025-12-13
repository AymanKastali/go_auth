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

func NewUserPostgresRepository(db *gorm.DB) repositories.UserRepositoryPort {
	return &UserPostgresRepository{db: db}
}

func (r *UserPostgresRepository) Save(u *entities.User) error {
	model := models.UserModel{
		ID:           u.ID().Value().String(),
		Email:        u.Email().Value(),
		PasswordHash: u.PasswordHash().Value(),
		IsActive:     u.IsActive(),
		Roles:        u.Roles().ToStrings(),
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
	// Convert string ID to UserID VO
	uid, err := uuid.Parse(model.ID)
	if err != nil {
		return nil, err
	}
	userID := valueobjects.UserIDFromUUID(uid)

	// Convert email
	email, err := valueobjects.NewEmail(model.Email)
	if err != nil {
		return nil, err
	}

	// Convert password hash
	pwHash := valueobjects.NewPasswordHash(model.PasswordHash)

	var roles valueobjects.Roles
	for _, r := range model.Roles {
		roles = append(roles, valueobjects.Role(r))
	}

	// Reconstruct domain user
	user := entities.NewUserFromPersistence(
		userID,
		email,
		pwHash,
		roles,
		model.IsActive,
		model.CreatedAt,
		model.UpdatedAt,
	)

	return user, nil
}

package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/ports/repositories"
	"go_auth/src/infra/mappers"

	"gorm.io/gorm"
)

type GormPermissionRepository struct {
	DB     *gorm.DB
	Mapper mappers.PermissionMapper
}

var _ repositories.PermissionRepositoryPort = (*GormPermissionRepository)(nil)

func NewGormPermissionRepository(
	db *gorm.DB,
	mapper mappers.PermissionMapper,
) repositories.PermissionRepositoryPort {
	return &GormPermissionRepository{
		DB:     db,
		Mapper: mapper,
	}
}

func (r *GormPermissionRepository) Save(permission *entities.Permission) error {

	permissionModel, err := r.Mapper.ToModel(permission)
	if err != nil {
		return err
	}

	result := r.DB.Save(permissionModel)

	return result.Error
}

// func (r *GormPermissionRepository) FindByID(id valueobjects.PermissionID) (*entities.Permission, error) {
// 	var permModel models.Permission

// 	modelID := id.Value.String()

// 	result := r.DB.First(&permModel, "id = ?", modelID)

// 	if result.Error != nil {
// 		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 			return nil, nil // Return nil entity if not found
// 		}
// 		return nil, result.Error
// 	}

// 	// Map the GORM model back to the Domain Entity
// 	return r.PermissionMapper.ToDomain(&permModel) // Mapper returns (entity, error)
// }

// // FindByKey retrieves a Permission by its unique key string (e.g., "user:create").
// func (r *GormPermissionRepository) FindByKey(key string) (*entities.Permission, error) {
// 	var permModel models.Permission

// 	// Query by the unique 'key' field
// 	result := r.DB.Where("key = ?", key).First(&permModel)

// 	if result.Error != nil {
// 		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 			return nil, nil
// 		}
// 		return nil, result.Error
// 	}

// 	return r.PermissionMapper.ToDomain(&permModel)
// }

// // FindAll retrieves all available Permissions.
// func (r *GormPermissionRepository) FindAll() ([]*entities.Permission, error) {
// 	var permModels []models.Permission

// 	result := r.DB.Find(&permModels)
// 	if result.Error != nil {
// 		return nil, result.Error
// 	}

// 	permissions := make([]*entities.Permission, 0, len(permModels))
// 	for i := range permModels {
// 		// Map each model to a domain entity.
// 		pEntity, err := r.PermissionMapper.ToDomain(&permModels[i])
// 		if err != nil {
// 			// Decide how to handle a single mapping error (e.g., corrupted UUID).
// 			// Here, we return the error immediately.
// 			return nil, err
// 		}
// 		permissions = append(permissions, pEntity)
// 	}

// 	return permissions, nil
// }

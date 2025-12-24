package repositories

import (
	"fmt"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres/models"
	"time"

	"gorm.io/gorm"
)

type GormDeviceRepository struct {
	db     *gorm.DB
	mapper *mappers.DeviceMapper
}

// Constructor
func NewGormDeviceRepository(
	db *gorm.DB,
	mapper *mappers.DeviceMapper,
) *GormDeviceRepository {
	return &GormDeviceRepository{
		db:     db,
		mapper: mapper,
	}
}

// GetByID fetches a device by its ID
func (r *GormDeviceRepository) GetByID(deviceID value_objects.DeviceId) (*entities.Device, error) {
	var model models.Device
	if err := r.db.Where("id = ?", deviceID.Value.String()).First(&model).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("device repository: failed to get device by ID: %w", err)
	}

	return r.mapper.ToDomain(&model)
}

// Upsert creates or updates a device
func (r *GormDeviceRepository) Upsert(device *entities.Device) error {
	model := r.mapper.ToModel(device)

	// Use GORM's "Save" to create or update based on primary key
	if err := r.db.Save(model).Error; err != nil {
		return fmt.Errorf("device repository: failed to upsert device: %w", err)
	}

	return nil
}

// Revoke marks a device as inactive and sets RevokedAt
func (r *GormDeviceRepository) Revoke(deviceID value_objects.DeviceId, revokedAt time.Time) error {
	if err := r.db.Model(&models.Device{}).
		Where("id = ?", deviceID.Value.String()).
		Updates(map[string]any{
			"is_active":  false,
			"revoked_at": revokedAt,
		}).Error; err != nil {
		return fmt.Errorf("device repository: failed to revoke device: %w", err)
	}
	return nil
}

// GetByUserID retrieves all devices for a user
func (r *GormDeviceRepository) GetByUserID(userID value_objects.UserId) ([]*entities.Device, error) {
	var modelsList []models.Device
	if err := r.db.Where("user_id = ?", userID.Value.String()).Find(&modelsList).Error; err != nil {
		return nil, fmt.Errorf("device repository: failed to get devices by user ID: %w", err)
	}

	devices := make([]*entities.Device, len(modelsList))
	for i := range modelsList {
		d, err := r.mapper.ToDomain(&modelsList[i])
		if err != nil {
			return nil, fmt.Errorf("device repository: failed to map device: %w", err)
		}
		devices[i] = d
	}

	return devices, nil
}

package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"

	"gorm.io/gorm"
)

type GormDeviceRepository struct {
	db     *gorm.DB
	mapper mappers.IDeviceMapper
}

func NewGormDeviceRepository(
	db *gorm.DB,
	mapper mappers.IDeviceMapper,
) *GormDeviceRepository {
	return &GormDeviceRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormDeviceRepository) GetByID(deviceID valueobjects.DeviceID) (*entities.Device, error) {
	var model models.Device
	err := r.db.Where("id = ?", deviceID.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Keeping nil, nil as your UseCase specifically checks 'if device == nil'
			// to decide between creating a new device or updating an existing one.
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormDeviceRepository) Upsert(device *entities.Device) error {
	if device == nil {
		return derr.ErrRequired("device entity")
	}

	model := r.mapper.ToModel(device)
	// GORM Save performs an upsert if the primary key is present
	err := r.db.Save(model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return derr.ErrDuplicate("device", device.ID().Value())
		}
		return err
	}
	return nil
}

func (r *GormDeviceRepository) Revoke(deviceID valueobjects.DeviceID, revokedAt time.Time) error {
	result := r.db.Model(&models.Device{}).
		Where("id = ? AND is_active = ?", deviceID.Value(), true).
		Updates(map[string]any{
			"is_active":  false,
			"revoked_at": revokedAt,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		// Specific business rule: Identify if the device wasn't found or was already inactive
		return derr.ErrNotFound("Active device", deviceID.Value())
	}

	return nil
}

func (r *GormDeviceRepository) GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error) {
	var modelsList []models.Device
	err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error
	if err != nil {
		return nil, err
	}

	devices := make([]*entities.Device, len(modelsList))
	for i := range modelsList {
		d, err := r.mapper.ToDomain(&modelsList[i])
		if err != nil {
			return nil, err
		}
		devices[i] = d
	}

	return devices, nil
}

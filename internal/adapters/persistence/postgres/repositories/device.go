package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr" // Use pgerr instead of derr
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
			return nil, nil // Nil for "not found" to support Use Case creation logic
		}
		// Wrap infrastructure/connection failures
		return nil, pgerr.WrapUnavailable(err, "failed to fetch device by id")
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormDeviceRepository) Upsert(device *entities.Device) error {
	model := r.mapper.ToModel(device)
	// GORM Save performs an upsert if the primary key is present
	err := r.db.Save(model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return pgerr.WrapAlreadyExists(err, "device already exists")
		}
		return pgerr.WrapUnavailable(err, "failed to upsert device")
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
		return pgerr.WrapUnavailable(result.Error, "failed to revoke device")
	}

	return nil
}

func (r *GormDeviceRepository) GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error) {
	var modelsList []models.Device
	err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error
	if err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to fetch devices by user id")
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

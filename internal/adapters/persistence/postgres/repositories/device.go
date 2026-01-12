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
			// Return nil result, nil error. Let the Use Case decide if this is an AppError.
			return nil, nil
		}
		return nil, err // Raw DB error (connection, etc.)
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormDeviceRepository) Upsert(device *entities.Device) error {
	model := r.mapper.ToModel(device)
	err := r.db.Save(model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// Translate DB tech into Domain intent
			return derr.NewViolation.DeviceAlreadyActive()
		}
		return err
	}
	return nil
}

func (r *GormDeviceRepository) Revoke(deviceID valueobjects.DeviceID, revokedAt time.Time) error {
	result := r.db.Model(&models.Device{}).
		Where("id = ?", deviceID.Value()).
		Updates(map[string]any{
			"is_active":  false,
			"revoked_at": revokedAt,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		// Specific business rule: Cannot revoke a non-existent/already revoked device
		return derr.NewViolation.DeviceRevoked()
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
			// Technical mapping error
			return nil, err
		}
		devices[i] = d
	}

	return devices, nil
}

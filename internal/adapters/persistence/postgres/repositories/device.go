package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/application/apperr"
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
	err := r.db.Where("id = ?", deviceID.String()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, r.handleError(err, deviceID.String())
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormDeviceRepository) Upsert(device *entities.Device) error {
	model := r.mapper.ToModel(device)
	// Save handles both INSERT and UPDATE based on Primary Key
	err := r.db.Save(model).Error
	return r.handleError(err, device.ID().String())
}

func (r *GormDeviceRepository) Revoke(deviceID valueobjects.DeviceID, revokedAt time.Time) error {
	result := r.db.Model(&models.Device{}).
		Where("id = ?", deviceID.String()).
		Updates(map[string]any{
			"is_active":  false,
			"revoked_at": revokedAt,
		})

	if result.Error != nil {
		return r.handleError(result.Error, deviceID.String())
	}

	if result.RowsAffected == 0 {
		return apperr.NewNotFoundErr("device", deviceID.String())
	}

	return nil
}

func (r *GormDeviceRepository) GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error) {
	var modelsList []models.Device
	err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error
	if err != nil {
		return nil, r.handleError(err, userID.Value())
	}

	devices := make([]*entities.Device, len(modelsList))
	for i := range modelsList {
		d, err := r.mapper.ToDomain(&modelsList[i])
		if err != nil {
			return nil, apperr.NewInternalErr("failed to map device from database")
		}
		devices[i] = d
	}

	return devices, nil
}

// Private helper to maintain architectural consistency
func (r *GormDeviceRepository) handleError(err error, id string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return apperr.NewAlreadyExistsErr("device", id)
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apperr.NewNotFoundErr("device", id)
	}

	return apperr.NewInternalErr(err.Error())
}

package repositories

import (
	"errors"
	"time"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/entities"
	domainports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormDeviceRepository struct {
	db     *gorm.DB
	mapper ports.IDeviceMapper
	idSvc  domainports.IIDService
}

func NewGormDeviceRepository(
	db *gorm.DB,
	mapper ports.IDeviceMapper,
	idSvc domainports.IIDService,
) *GormDeviceRepository {
	return &GormDeviceRepository{
		db:     db,
		mapper: mapper,
		idSvc:  idSvc,
	}
}

func (r *GormDeviceRepository) GetByID(deviceID valueobjects.DeviceID) (*entities.Device, error) {
	var model models.Device
	err := r.db.Where("id = ?", deviceID.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch device")
	}

	if err := model.Validate(r.idSvc); err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

func (r *GormDeviceRepository) GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error) {
	var modelsList []models.Device
	err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error
	if err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to fetch user devices")
	}

	devices := make([]*entities.Device, len(modelsList))
	for i := range modelsList {
		// ALL OR NOTHING: Validate every item in the list
		if err := modelsList[i].Validate(r.idSvc); err != nil {
			return nil, err
		}
		devices[i] = r.mapper.ToDomain(&modelsList[i])
	}

	return devices, nil
}

func (r *GormDeviceRepository) Upsert(e *entities.Device) error {
	model := r.mapper.ToModel(e)
	if err := r.db.Save(model).Error; err != nil {
		return pgerr.WrapUnavailable(err, "failed to save device")
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

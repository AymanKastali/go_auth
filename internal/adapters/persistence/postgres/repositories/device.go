package repositories

import (
	"errors"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/entities"
	domainports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type gormDeviceRepository struct {
	db     *gorm.DB
	mapper ports.IDeviceMapper
	idSvc  domainports.IIDService
}

func NewGormDeviceRepository(
	db *gorm.DB,
	mapper ports.IDeviceMapper,
	idSvc domainports.IIDService,
) *gormDeviceRepository {
	return &gormDeviceRepository{
		db:     db,
		mapper: mapper,
		idSvc:  idSvc,
	}
}

func (r *gormDeviceRepository) GetByID(id valueobjects.DeviceID) (*entities.Device, error) {
	var model models.Device

	err := r.db.Where("id = ?", id.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

func (r *gormDeviceRepository) GetByFingerprint(fingerprint valueobjects.DeviceFingerprint) (*entities.Device, error) {
	var model models.Device
	err := r.db.Where("fingerprint = ?", fingerprint.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch device")
	}

	return r.mapper.ToDomain(&model), nil
}

func (r *gormDeviceRepository) GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error) {
	var modelsList []models.Device
	err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error
	if err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to fetch user devices")
	}

	devices := make([]*entities.Device, len(modelsList))
	for i := range modelsList {
		devices[i] = r.mapper.ToDomain(&modelsList[i])
	}

	return devices, nil
}

func (r *gormDeviceRepository) Upsert(e *entities.Device) error {
	model := r.mapper.ToModel(e)
	if err := r.db.Save(model).Error; err != nil {
		return pgerr.WrapUnavailable(err, "failed to save device")
	}
	return nil
}

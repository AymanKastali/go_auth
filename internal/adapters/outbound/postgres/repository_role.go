package postgres

import (
	"context"
	"errors"
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

type postgresRoleRepository struct {
	db *gorm.DB
}

func NewPostgresRoleRepository(db *gorm.DB) domain.IRoleRepository {
	return &postgresRoleRepository{db: db}
}

func (r *postgresRoleRepository) FindByID(ctx context.Context, id domain.RoleID) (*domain.Role, error) {
	var model RoleModel
	err := getDB(r.db, ctx).
		Preload("Permissions").
		Where("ulid = ?", id.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toRoleDomain(model), nil
}

func (r *postgresRoleRepository) FindByName(ctx context.Context, name domain.RoleName) (*domain.Role, error) {
	var model RoleModel
	err := getDB(r.db, ctx).
		Preload("Permissions").
		Where("name = ?", name.Name()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toRoleDomain(model), nil
}

func (r *postgresRoleRepository) FindAll(ctx context.Context) ([]*domain.Role, error) {
	var models []RoleModel
	err := getDB(r.db, ctx).
		Preload("Permissions").
		Find(&models).Error

	if err != nil {
		return nil, domain.ErrInternal
	}

	roles := make([]*domain.Role, len(models))
	for i, m := range models {
		roles[i] = toRoleDomain(m)
	}
	return roles, nil
}

func (r *postgresRoleRepository) Save(ctx context.Context, role *domain.Role) error {
	model := toRoleModel(role)
	db := getDB(r.db, ctx)

	// Resolve own PK
	pk, err := resolvePK(db, &RoleModel{}, model.ULID)
	if err != nil {
		return err
	}
	model.ID = pk

	// Save the role record itself (omit associations to avoid FK ordering issues)
	if err := db.Omit("Permissions").Save(&model).Error; err != nil {
		return domain.ErrInternal
	}

	// Replace permissions: delete existing, insert current with resolved PK
	if err := db.Where("role_id = ?", model.ID).Delete(&PermissionModel{}).Error; err != nil {
		return domain.ErrInternal
	}
	if len(model.Permissions) > 0 {
		for i := range model.Permissions {
			model.Permissions[i].RoleID = model.ID
		}
		if err := db.Create(&model.Permissions).Error; err != nil {
			return domain.ErrInternal
		}
	}

	return nil
}

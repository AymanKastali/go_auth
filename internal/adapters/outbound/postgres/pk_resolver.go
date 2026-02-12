package postgres

import (
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

// resolvePK looks up the integer PK for an aggregate given its ULID.
// Returns 0 if the record does not exist yet (new record).
func resolvePK(db *gorm.DB, model any, ulidVal string) (uint, error) {
	var id uint
	err := db.Model(model).
		Select("id").
		Where("ulid = ?", ulidVal).
		Scan(&id).Error
	if err != nil {
		return 0, domain.ErrInternal
	}
	return id, nil
}

// resolveUserPK looks up a User integer PK by ULID.
// Returns an error if the user does not exist (cross-aggregate FK must exist).
func resolveUserPK(db *gorm.DB, userULID string) (uint, error) {
	var id uint
	err := db.Model(&UserModel{}).
		Select("id").
		Where("ulid = ?", userULID).
		Scan(&id).Error
	if err != nil {
		return 0, domain.ErrInternal
	}
	if id == 0 {
		return 0, domain.ErrUserNotFound
	}
	return id, nil
}

package models

import (
	"gorm.io/gorm"
)

type Organization struct {
	gorm.Model
	ID          string       `gorm:"primaryKey;type:uuid"`
	Name        string       `gorm:"not null"`
	OwnerUserID string       `gorm:"type:uuid;not null;index"`
	Status      string       `gorm:"type:varchar(20);not null"`
	Memberships []Membership `gorm:"foreignKey:OrganizationID"`
	Owner       User         `gorm:"foreignKey:OwnerUserID"`
}

func (Organization) TableName() string {
	return "organizations"
}

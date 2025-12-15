package models

import (
	"gorm.io/gorm"
)

type Membership struct {
	gorm.Model
	UserID         string       `gorm:"type:uuid;not null;index"`
	OrganizationID string       `gorm:"type:uuid;not null;index"`
	Role           string       `gorm:"type:varchar(20);not null"`
	Status         string       `gorm:"type:varchar(20);not null"`
	User           User         `gorm:"foreignKey:UserID"`
	Organization   Organization `gorm:"foreignKey:OrganizationID"`
}

func (Membership) TableName() string {
	return "memberships"
}

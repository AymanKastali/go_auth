package models

import (
	"gorm.io/gorm"
)

type Membership struct {
	gorm.Model
	ID             string       `gorm:"primaryKey;type:uuid"`
	UserID         string       `gorm:"type:uuid;not null;index"`
	OrganizationID string       `gorm:"type:uuid;not null;index"`
	Role           string       `gorm:"type:varchar(20);not null"`
	Status         string       `gorm:"type:varchar(20);not null"`
	User           User         `gorm:"foreignKey:UserID"`
	Organization   Organization `gorm:"foreignKey:OrganizationID"`
	Roles          []string     `gorm:"serializer:json"`
}

func (Membership) TableName() string {
	return "memberships"
}

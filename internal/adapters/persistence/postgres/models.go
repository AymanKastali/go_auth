package postgres

import (
	"time"
)

type UserModel struct {
	ID           string     `gorm:"primaryKey;column:id"`
	Email        string     `gorm:"uniqueIndex;column:email"`
	PasswordHash string     `gorm:"column:password_hash"`
	IsActive     bool       `gorm:"column:is_active"`
	Roles        []string   `gorm:"serializer:json;column:roles;type:jsonb"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
	UpdatedAt    time.Time  `gorm:"column:updated_at"`
	DeletedAt    *time.Time `gorm:"column:deleted_at;index"`

	Sessions []SessionModel `gorm:"foreignKey:user_id"`
}

func (UserModel) TableName() string { return "users" }

type SessionModel struct {
	ID             string     `gorm:"primaryKey;column:id"`
	UserID         string     `gorm:"index;column:user_id"`
	HashedToken    string     `gorm:"type:varchar(255);uniqueIndex;not null"`
	IPAddress      string     `gorm:"column:ip_address;type:varchar(45)"`
	UserAgent      string     `gorm:"column:user_agent;type:text"`
	OS             string     `gorm:"column:os;type:varchar(100)"`
	Browser        string     `gorm:"column:browser;type:varchar(100)"`
	Model          string     `gorm:"column:model;type:varchar(100)"`
	AcceptLanguage string     `gorm:"column:accept_language;type:varchar(10)"`
	IsMobile       bool       `gorm:"column:is_mobile"`
	ExpiresAt      time.Time  `gorm:"column:expires_at"`
	LastActiveAt   time.Time  `gorm:"column:last_active_at"`
	RevokedAt      *time.Time `gorm:"column:revoked_at"`
}

func (SessionModel) TableName() string { return "sessions" }

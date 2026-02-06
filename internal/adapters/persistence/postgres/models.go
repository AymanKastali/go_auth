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
	RegisteredAt time.Time  `gorm:"column:registered_at"`
	UpdatedAt    time.Time  `gorm:"column:updated_at;autoUpdateTime"`
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
	IsRevoked      bool       `gorm:"column:is_revoked"`
}

func (SessionModel) TableName() string { return "sessions" }

type RecoveryTokenModel struct {
	ID          string     `gorm:"primaryKey;column:id"`
	UserID      string     `gorm:"index;column:user_id;not null"`
	HashedToken string     `gorm:"uniqueIndex;column:hashed_token;not null"`
	ExpiresAt   time.Time  `gorm:"column:expires_at;not null"`
	CreatedAt   time.Time  `gorm:"column:created_at;autoCreateTime"`
	IsUsed      bool       `gorm:"column:is_used"`
}

func (RecoveryTokenModel) TableName() string { return "recovery_tokens" }

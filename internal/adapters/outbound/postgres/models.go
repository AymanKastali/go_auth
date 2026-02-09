package postgres

import (
	"time"
)

type UserModel struct {
	ID           string          `gorm:"primaryKey;column:id"`
	Email        string          `gorm:"uniqueIndex;column:email"`
	PasswordHash string          `gorm:"column:password_hash"`
	IsActive     bool            `gorm:"column:is_active"`
	UserRoles    []UserRoleModel `gorm:"foreignKey:UserID"`
	RegisteredAt time.Time       `gorm:"column:registered_at"`
	UpdatedAt    time.Time       `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt    *time.Time      `gorm:"column:deleted_at;index"`
}

func (UserModel) TableName() string { return "users" }

type UserRoleModel struct {
	UserID   string `gorm:"primaryKey;column:user_id"`
	RoleName string `gorm:"primaryKey;column:role_name"`
}

func (UserRoleModel) TableName() string { return "user_roles" }

type SessionModel struct {
	ID             string    `gorm:"primaryKey;column:id"`
	UserID         string    `gorm:"index;column:user_id"`
	HashedToken    string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	Fingerprint    string    `gorm:"column:fingerprint;type:varchar(255);index"`
	IPAddress      string    `gorm:"column:ip_address;type:varchar(45)"`
	UserAgent      string    `gorm:"column:user_agent;type:text"`
	OS             string    `gorm:"column:os;type:varchar(100)"`
	Browser        string    `gorm:"column:browser;type:varchar(100)"`
	Model          string    `gorm:"column:model;type:varchar(100)"`
	AcceptLanguage string    `gorm:"column:accept_language;type:varchar(10)"`
	IsMobile       bool      `gorm:"column:is_mobile"`
	ExpiresAt      time.Time `gorm:"column:expires_at"`
	LastActiveAt   time.Time `gorm:"column:last_active_at"`
	IsRevoked      bool      `gorm:"column:is_revoked"`
}

func (SessionModel) TableName() string { return "sessions" }

type RecoveryTokenModel struct {
	ID          string    `gorm:"primaryKey;column:id"`
	UserID      string    `gorm:"index;column:user_id;not null"`
	HashedToken string    `gorm:"uniqueIndex;column:hashed_token;not null"`
	ExpiresAt   time.Time `gorm:"column:expires_at;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime"`
	IsUsed      bool      `gorm:"column:is_used"`
}

func (RecoveryTokenModel) TableName() string { return "recovery_tokens" }

type ActivationTokenModel struct {
	ID          string    `gorm:"primaryKey;column:id"`
	UserID      string    `gorm:"index;column:user_id;not null"`
	HashedToken string    `gorm:"uniqueIndex;column:hashed_token;not null"`
	ExpiresAt   time.Time `gorm:"column:expires_at;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime"`
	IsUsed      bool      `gorm:"column:is_used"`
}

func (ActivationTokenModel) TableName() string { return "activation_tokens" }

type RoleModel struct {
	ID          string            `gorm:"primaryKey;column:id"`
	Name        string            `gorm:"uniqueIndex;column:name;not null"`
	Description string            `gorm:"column:description;type:text"`
	CreatedAt   time.Time         `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt   time.Time         `gorm:"column:updated_at;autoUpdateTime"`
	Permissions []PermissionModel `gorm:"foreignKey:RoleID"`
}

func (RoleModel) TableName() string { return "roles" }

type PermissionModel struct {
	ID       string `gorm:"primaryKey;column:id"`
	RoleID   string `gorm:"index;column:role_id;not null"`
	Resource string `gorm:"column:resource;not null"`
	Action   string `gorm:"column:action;not null"`
}

func (PermissionModel) TableName() string { return "permissions" }

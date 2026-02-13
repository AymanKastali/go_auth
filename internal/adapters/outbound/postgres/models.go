package postgres

import (
	"time"

	"gorm.io/gorm"
)

// --- Aggregate Models (gorm.Model provides ID uint, CreatedAt, UpdatedAt, DeletedAt) ---

type UserModel struct {
	gorm.Model
	ULID         string          `gorm:"uniqueIndex;column:ulid;not null"`
	Email        string          `gorm:"uniqueIndex;column:email"`
	PasswordHash string          `gorm:"column:password_hash"`
	IsActive     bool            `gorm:"column:is_active"`
	UserRoles    []UserRoleModel `gorm:"foreignKey:UserID"`
}

func (UserModel) TableName() string { return "users" }

type SessionModel struct {
	gorm.Model
	ULID               string    `gorm:"uniqueIndex;column:ulid;not null"`
	UserID             uint      `gorm:"index;column:user_id"`
	UserULID           string    `gorm:"index;column:user_ulid;not null"`
	HashedToken        string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	PreviousHashedToken string   `gorm:"type:varchar(255);index;column:previous_hashed_token"`
	Fingerprint        string    `gorm:"column:fingerprint;type:varchar(255);index"`
	IPAddress          string    `gorm:"column:ip_address;type:varchar(45)"`
	UserAgent          string    `gorm:"column:user_agent;type:text"`
	OS                 string    `gorm:"column:os;type:varchar(100)"`
	Browser            string    `gorm:"column:browser;type:varchar(100)"`
	DeviceModel        string    `gorm:"column:device_model;type:varchar(100)"`
	AcceptLanguage     string    `gorm:"column:accept_language;type:varchar(10)"`
	IsMobile           bool      `gorm:"column:is_mobile"`
	ExpiresAt          time.Time `gorm:"column:expires_at"`
	LastActiveAt       time.Time `gorm:"column:last_active_at"`
	IsRevoked          bool      `gorm:"column:is_revoked"`
}

func (SessionModel) TableName() string { return "sessions" }

type RoleModel struct {
	gorm.Model
	ULID        string            `gorm:"uniqueIndex;column:ulid;not null"`
	Name        string            `gorm:"uniqueIndex;column:name;not null"`
	Description string            `gorm:"column:description;type:text"`
	Permissions []PermissionModel `gorm:"foreignKey:RoleID"`
}

func (RoleModel) TableName() string { return "roles" }

type RecoveryTokenModel struct {
	gorm.Model
	ULID        string    `gorm:"uniqueIndex;column:ulid;not null"`
	UserID      uint      `gorm:"index;column:user_id;not null"`
	UserULID    string    `gorm:"index;column:user_ulid;not null"`
	HashedToken string    `gorm:"uniqueIndex;column:hashed_token;not null"`
	ExpiresAt   time.Time `gorm:"column:expires_at;not null"`
	IsUsed      bool      `gorm:"column:is_used"`
}

func (RecoveryTokenModel) TableName() string { return "recovery_tokens" }

type ActivationTokenModel struct {
	gorm.Model
	ULID        string    `gorm:"uniqueIndex;column:ulid;not null"`
	UserID      uint      `gorm:"index;column:user_id;not null"`
	UserULID    string    `gorm:"index;column:user_ulid;not null"`
	HashedToken string    `gorm:"uniqueIndex;column:hashed_token;not null"`
	ExpiresAt   time.Time `gorm:"column:expires_at;not null"`
	IsUsed      bool      `gorm:"column:is_used"`
}

func (ActivationTokenModel) TableName() string { return "activation_tokens" }

// --- Sub-entity / Junction Models (simple auto-increment PK, no gorm.Model) ---

type UserRoleModel struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	UserID   uint   `gorm:"uniqueIndex:idx_user_role;column:user_id"`
	RoleName string `gorm:"uniqueIndex:idx_user_role;column:role_name"`
}

func (UserRoleModel) TableName() string { return "user_roles" }

type PermissionModel struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	RoleID   uint   `gorm:"index;column:role_id;not null"`
	Resource string `gorm:"column:resource;not null"`
	Action   string `gorm:"column:action;not null"`
}

func (PermissionModel) TableName() string { return "permissions" }

package domain

import (
	"context"
)

// Infrastructure ports (adapter-implemented)

type IClock interface {
	Now() Timepoint
}
type IPasswordService interface {
	Hash(raw RawPassword) (HashedPassword, error)
	Compare(raw RawPassword, hashed HashedPassword) bool
}
type IIDGenerator interface {
	GenerateUserID() (UserID, error)
	GenerateSessionID() (SessionID, error)
	GenerateRecoveryTokenID() (RecoveryTokenID, error)
	GenerateActivationTokenID() (ActivationTokenID, error)
	GenerateRoleID() (RoleID, error)
}
type ITokenService interface {
	Generate() (RawToken, error)

	HashSessionToken(raw RawToken) (HashedToken, error)
	HashRecoveryToken(raw RawToken) (RecoveryTokenHash, error)
	HashActivationToken(raw RawToken) (ActivationTokenHash, error)

	CompareSession(raw RawToken, hashed HashedToken) bool
	CompareRecovery(raw RawToken, hashed RecoveryTokenHash) bool
	CompareActivation(raw RawToken, hashed ActivationTokenHash) bool
}
type IAccessService interface {
	Issue(
		userID UserID,
		email Email,
		sessionID SessionID,
		roles []RoleName,
		permissions []Permission,
		IssuedAt Timepoint,
		expiresAt Timepoint,
		notBefore Timepoint,
	) (AccessToken, Timepoint, error)
	Validate(token AccessToken) (AccessIdentity, error)
}

// Domain service ports (adapter-implemented)

type IRegistrationRoleProvider interface {
	DefaultMemberRole(ctx context.Context) (RoleName, error)
	DefaultAdminRole(ctx context.Context) (RoleName, error)
}

// Repository ports (adapter-implemented)

type IUserRepository interface {
	FindByID(ctx context.Context, id UserID) (*User, error)
	FindByEmail(ctx context.Context, email Email) (*User, error)
	FindAll(ctx context.Context, offset, limit int) ([]*User, error)
	Count(ctx context.Context) (int64, error)
	Save(ctx context.Context, user *User) error
	Delete(ctx context.Context, id UserID) error
}

type ISessionRepository interface {
	FindByID(ctx context.Context, id SessionID) (*Session, error)
	FindByToken(ctx context.Context, token HashedToken) (*Session, error)
	FindActiveByUserAndFingerprint(ctx context.Context, userID UserID, fp DeviceFingerprint) (*Session, error)
	FindActiveByUserID(ctx context.Context, userID UserID) ([]*Session, error)
	Save(ctx context.Context, session *Session) error
	RevokeAllForUser(ctx context.Context, userID UserID, now Timepoint) error
}

type IRoleRepository interface {
	FindByID(ctx context.Context, id RoleID) (*Role, error)
	FindByName(ctx context.Context, name RoleName) (*Role, error)
	FindAll(ctx context.Context) ([]*Role, error)
	Save(ctx context.Context, role *Role) error
}

type IRecoveryTokenRepository interface {
	FindByHash(ctx context.Context, hash RecoveryTokenHash) (*RecoveryToken, error)
	Save(ctx context.Context, token *RecoveryToken) error
	RevokeAllForUser(ctx context.Context, uid UserID, now Timepoint) error
}

type IActivationTokenRepository interface {
	FindByHash(ctx context.Context, hash ActivationTokenHash) (*ActivationToken, error)
	Save(ctx context.Context, token *ActivationToken) error
	RevokeAllForUser(ctx context.Context, uid UserID, now Timepoint) error
}

package domain

import (
	"context"
	"time"
)

// Repositories
type IUserRepository interface {
	FindByID(ctx context.Context, id UserID) (*User, error)
	FindByEmail(ctx context.Context, email Email) (*User, error)
	Save(ctx context.Context, user *User) error
	Delete(ctx context.Context, id UserID) error
	FindBySessionToken(ctx context.Context, token HashedToken) (*User, error)
}

type IRecoveryTokenRepository interface {
	FindByHash(ctx context.Context, hash RecoveryTokenHash) (*RecoveryToken, error)
	Save(ctx context.Context, token *RecoveryToken) error
	RevokeAllForUser(ctx context.Context, uid UserID, now Timepoint) error
}

// Services
type IIDGenerator interface {
	Generate() (string, error)
}

type ITokenService interface {
	Generate() (RawToken, error)
	Hash(rawToken RawToken) (HashedToken, error)
	Compare(raw RawToken, hashed HashedToken) bool
}

type IClock interface {
	Now() Timepoint
}

type IPasswordService interface {
	Hash(plain RawPassword) (HashedPassword, error)
	Compare(plain RawPassword, hashed HashedPassword) bool
}

type IRegisterUserService interface {
	Execute(
		ctx context.Context,
		email Email,
		password RawPassword,
	) (*User, error)
}

type IRefreshSession interface {
	Execute(
		ctx context.Context,
		raw RawToken,
		currentFingerprint DeviceFingerprint,
	) (*User, Session, error)
}

type IAuthenticateUser interface {
	Execute(
		ctx context.Context,
		email Email,
		password RawPassword,
	) (*User, error)
}

type IEstablishUserSession interface {
	Execute(
		ctx context.Context,
		user *User,
		deviceIdentity DeviceIdentity,
	) (*Session, RawToken, error)
}

// Services
// requirement for the "Login" and "Refresh" use cases.
type IAccessTokenService interface {
	Issue(
		userID UserID,
		email Email,
		sessionID SessionID,
		roles []Role,
		IssuedAt Timepoint,
		expiresAt Timepoint,
		notBefore Timepoint,
	) (AccessToken, Timepoint, error)
	Validate(token AccessToken) (AccessIdentity, error)
}

// Factories
type IUserFactory interface {
	Build(
		id UserID,
		email Email,
		password HashedPassword,
		createdAt Timepoint,
	) (*User, error)
}

type ISessionFactory interface {
	Build(
		id SessionID,
		token HashedToken,
		identity DeviceIdentity,
		expiresAt Timepoint,
		now Timepoint,
	) (*Session, error)
}

// Policies
type IPasswordPolicy interface {
	// Validate checks if a RawPassword meets complexity requirements.
	Validate(rawPassword RawPassword) error
}

type ISessionPolicy interface {
	// GetExpiryDuration returns how long a session should remain valid.
	GetSessionLifetime() time.Duration
	// GetMaxActiveSessions returns the limit of concurrent sessions per user.
	GetMaxActiveSessions() int
}

// Access
type IAccessPolicy interface {
	GetAccessLifetime() time.Duration
}

type IAccessGrantor interface {
	GrantImmediateAccess(
		ctx context.Context,
		user *User,
		sessionID SessionID,
	) (AccessToken, Timepoint, error)
}

type IChangePassword interface {
	ChangePassword(
		ctx context.Context,
		user *User,
		oldPassword RawPassword,
		newPassword RawPassword,
	) error
}

type IPasswordResetService interface {
	Reset(
		ctx context.Context,
		rawToken RawToken,
		newPassword RawPassword,
		now Timepoint,
	) error
}

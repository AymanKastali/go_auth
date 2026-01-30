package domain

import (
	"context"
	"time"
)

type IUserAccountManager interface {
	InitiatePasswordReset(
		ctx context.Context,
		user *User,
		now Timepoint,
	) (RawToken, *RecoveryToken, error)
	ChangePassword(
		ctx context.Context,
		user *User,
		oldPass RawPassword,
		newPass RawPassword,
		now Timepoint,
	) error
	ResetPasswordByToken(
		ctx context.Context,
		token RawToken,
		newPassword RawPassword,
		now Timepoint,
	) error
}

type IAccessManager interface {
	GrantImmediateAccess(
		user *User,
		sid SessionID,
		now Timepoint,
	) (AccessToken, Timepoint, error)
	VerifyAccess(
		ctx context.Context,
		token AccessToken,
		now Timepoint,
	) (*User, SessionID, error)
}

// Policies
type IPasswordPolicy interface {
	Validate(rawPassword RawPassword) error
}
type IRegisterPolicy interface {
	Validate(email Email) error
}
type IAccessPolicy interface {
	GetAccessLifetime() time.Duration
}
type ISessionPolicy interface {
	GetSessionLifetime() time.Duration
	GetMaxActiveSessions() int
}

// Services
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
}
type ITokenService interface {
	Generate() (RawToken, error)

	HashSessionToken(raw RawToken) (HashedToken, error)
	HashRecoveryToken(raw RawToken) (RecoveryTokenHash, error)

	CompareSession(raw RawToken, hashed HashedToken) bool
	CompareRecovery(raw RawToken, hashed RecoveryTokenHash) bool
}
type IAccessService interface {
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

type IRegistrationService interface {
	RegisterNewMember(
		ctx context.Context,
		id UserID,
		email Email,
		pwd HashedPassword,
		now Timepoint,
	) (*User, error)
	RegisterNewSuperAdmin(
		ctx context.Context,
		id UserID,
		email Email,
		pwd HashedPassword,
		now Timepoint,
	) (*User, error)
}

type IAuthenticationService interface {
	AuthenticateAndEstablishSession(
		ctx context.Context,
		user *User,
		rawPassword RawPassword,
		identity DeviceIdentity,
		now Timepoint,
	) (RawToken, Session, error)
	RefreshSession(
		ctx context.Context,
		rawToken RawToken,
		fp DeviceFingerprint,
		now Timepoint,
	) (*User, Session, error)
}

type IPasswordManager interface {
	ValidateAndHashNewPassword(raw RawPassword) (HashedPassword, error)
	Compare(raw RawPassword, hashed HashedPassword) bool
}

//

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

// Policies
type IRecoveryPolicy interface {
	GetRecoveryTokenLifetime() time.Duration
}

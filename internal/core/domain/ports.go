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

// Repository ports (adapter-implemented)

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

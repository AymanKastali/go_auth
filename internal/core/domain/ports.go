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
}

// Services
type IIDGenerator interface {
	GenerateUserID(ctx context.Context) (UserID, error)
	GenerateSessionID(ctx context.Context) (SessionID, error)
}

type ITokenService interface {
	Generate() (RawToken, HashedToken, error)
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

type IUserRegistrationService interface {
	// Register ensures the email is unique before creating the User.
	// It coordinates the Repository and the IDGenerator.
	Register(
		ctx context.Context,
		email Email,
		password RawPassword,
	) (*User, error)
}

type IAuthenticationService interface {
	// Authenticate verifies credentials and, if successful, adds a Session to the User.
	// It returns the User (with the new session) and the RawToken to be sent to the client.
	Authenticate(
		ctx context.Context,
		email Email,
		password RawPassword,
		identity DeviceIdentity,
	) (*User, Session, RawToken, error)

	RefreshUserSession(
		ctx context.Context,
		uid UserID,
		raw RawToken,
		currentFingerprint DeviceFingerprint,
	) (*User, Session, error)
}

type IIdentityGuardService interface {
	// CheckIntegrity validates if the user and session are currently fit for use.
	CheckIntegrity(user *User, sid SessionID) error
}

// Services
// requirement for the "Login" and "Refresh" use cases.
type IAccessTokenProvider interface {
	// Generate creates a signed token and returns its expiry time.
	Generate(user *User, sid SessionID) (AccessToken, Timepoint, error)
	Validate(token AccessToken) (AccessIdentity, error)
}

// Factories
type IUserFactory interface {
	// Build assembles a new User aggregate root.
	// It is "dumb" because it receives pre-computed values.
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
	GetExpiryDuration() time.Duration

	// GetMaxActiveSessions returns the limit of concurrent sessions per user.
	GetMaxActiveSessions() int
}

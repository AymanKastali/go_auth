package services

import (
	"go_auth/src/domain/errors"
	"go_auth/src/domain/ports/repositories"
	portservices "go_auth/src/domain/ports/services"
	valueobjects "go_auth/src/domain/value_objects"
)

// AuthenticateUser is a TRUE Domain Service (not a port/interface).
// It coordinates:
// - User Repository
// - Password Service
// - Token Service
// to perform authentication and issue a STATELESS JWT.
type AuthenticateUser struct {
	Users    repositories.UserRepository
	Token    portservices.TokenService
	Password portservices.PasswordService
}

// Execute authenticates the user and issues a stateless JWT access token.
func (s *AuthenticateUser) Execute(
	email valueobjects.Email,
	rawPassword string,
) (*valueobjects.AccessToken, error) {

	// 1️⃣ Load User
	user, err := s.Users.GetByEmail(email)
	if err != nil || user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	// 2️⃣ Verify password
	if !s.Password.Compare(rawPassword, user.PasswordHash().Value()) {
		return nil, errors.ErrInvalidCredentials
	}

	// 3️⃣ Issue STATELESS access token
	accessToken, err := s.Token.IssueAccessToken(user)
	if err != nil {
		return nil, err
	}

	// ✅ NO SESSION
	// ✅ NO REDIS
	// ✅ NO TOKEN PERSISTENCE
	// ✅ JWT IS FULLY STATELESS

	return &accessToken, nil
}

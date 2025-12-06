package services

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/ports/repositories"
	portservices "go_auth/src/domain/ports/services"
	valueobjects "go_auth/src/domain/value_objects"
)

type AuthenticateUser struct {
	Users    repositories.UserRepository
	Tokens   repositories.TokenSessionRepository
	Token    portservices.TokenService
	Password portservices.PasswordHasher
}

func (s *AuthenticateUser) Execute(
	email valueobjects.Email,
	password string,
) (*valueobjects.AccessToken, error) {

	user, err := s.Users.GetByEmail(email)
	if err != nil || user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	if !s.Password.Verify(password, user.PasswordHash) {
		return nil, errors.ErrInvalidCredentials
	}

	accessToken := s.Token.IssueAccessToken(user)

	session := entities.NewTokenSession(
		accessToken.JTI,
		accessToken.UserID,
		accessToken.ExpiresAt,
	)

	_ = s.Tokens.Save(session)

	return &accessToken, nil
}

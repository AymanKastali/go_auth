package services

import (
	valueobjects "go_auth/src/domain/value_objects"
)

type TokenServicePort interface {
	IssueAccessToken(userID string, roles []string) (valueobjects.JWTToken, error)
	IssueRefreshToken(userID string) (valueobjects.JWTToken, error)
}

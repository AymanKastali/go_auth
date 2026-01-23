package ports

import (
	"go_auth/internal/core/application/dto"
)

type ISessionTokenIssuerService interface {
	Issue(ctx dto.SessionTokenMetadata) (dto.IssuedSessionToken, error)
	Validate(raw string) (dto.SessionTokenMetadata, error)
}

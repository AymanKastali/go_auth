package jwt

import (
	"crypto/rsa"
	"go_auth/internal/core/application/dto"

	"github.com/golang-jwt/jwt/v5"
)

type sessionClaims struct {
	Roles    []string `json:"roles"`
	DeviceID string   `json:"did"`
	jwt.RegisteredClaims
}

type jwtSessionTokenIssuerService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
}

func NewJWTSessionTokenIssuerService(
	private *rsa.PrivateKey,
	public *rsa.PublicKey,
	issuer string,
	audience string,
) *jwtSessionTokenIssuerService {
	return &jwtSessionTokenIssuerService{
		privateKey: private,
		publicKey:  public,
		issuer:     issuer,
		audience:   audience,
	}
}

func (s *jwtSessionTokenIssuerService) Issue(
	ctx dto.IssueSessionToken,
) (dto.IssuedSessionToken, error) {

	claims := sessionClaims{
		Roles:    ctx.Roles,
		DeviceID: ctx.DeviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   ctx.UserID,
			Audience:  []string{s.audience},
			ID:        ctx.TokenID,
			IssuedAt:  jwt.NewNumericDate(ctx.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(ctx.ExpiresAt),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := t.SignedString(s.privateKey)
	if err != nil {
		return dto.IssuedSessionToken{}, err
	}

	return dto.IssuedSessionToken{Raw: signed}, nil
}

func (s *jwtSessionTokenIssuerService) Validate(
	raw string,
) (dto.SessionTokenMetadata, error) {

	claims := &sessionClaims{}

	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		return s.publicKey, nil
	})
	if err != nil {
		return dto.SessionTokenMetadata{}, err
	}

	return dto.SessionTokenMetadata{
		TokenID:   claims.ID,
		UserID:    claims.Subject,
		DeviceID:  claims.DeviceID,
		Roles:     claims.Roles,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

package adapters

import (
	"errors"
	"go_auth/internal/core/domain"

	"github.com/golang-jwt/jwt/v5"
)

// JWT Service
type jwtService struct {
	secretKey []byte
	issuer    string
	audience  string
}

func NewJWTService(
	secret string,
	issuer string,
	audience string,
) domain.IAccessService {
	return &jwtService{
		secretKey: []byte(secret),
		issuer:    issuer,
		audience:  audience,
	}
}

type CustomClaims struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	SID   string   `json:"sid"`
	jwt.RegisteredClaims
}

func (p *jwtService) Issue(
	userID domain.UserID,
	email domain.Email,
	sessionID domain.SessionID,
	roles []domain.Role,
	IssuedAt domain.Timepoint,
	expiresAt domain.Timepoint,
	notBefore domain.Timepoint,
) (domain.AccessToken, domain.Timepoint, error) {
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name()
	}

	claims := CustomClaims{
		Email: email.String(),
		Roles: roleNames,
		SID:   sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(IssuedAt.Time()),
			ExpiresAt: jwt.NewNumericDate(expiresAt.Time()),
			NotBefore: jwt.NewNumericDate(notBefore.Time()),
			Issuer:    p.issuer,
			Audience:  jwt.ClaimStrings{p.audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedStr, err := token.SignedString(p.secretKey)
	if err != nil {
		return domain.ZeroAccessToken, domain.ZeroTimepoint, domain.ErrInternal
	}

	accessToken, err := domain.NewAccessToken(signedStr)
	if err != nil {
		return domain.ZeroAccessToken, domain.ZeroTimepoint, err
	}

	return accessToken, expiresAt, nil
}

func (p *jwtService) Validate(token domain.AccessToken) (domain.AccessIdentity, error) {
	// 1. Technical Parse with Claims Validation
	parsedToken, err := jwt.ParseWithClaims(
		token.String(),
		&CustomClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return p.secretKey, nil
		},
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.audience),
	)

	// 2. Map Infrastructure Errors
	if err != nil || !parsedToken.Valid {
		return domain.ZeroAccessIdentity, domain.ErrTokenInvalid
	}

	// 3. Technical Extraction
	claims, ok := parsedToken.Claims.(*CustomClaims)
	if !ok {
		return domain.ZeroAccessIdentity, domain.ErrTokenInvalid
	}

	// 4. Reconstitute Domain VOs
	uid, err := domain.NewUserID(claims.Subject)
	if err != nil {
		return domain.ZeroAccessIdentity, err
	}

	// Use the Custom SID claim, NOT the JTI
	sid, err := domain.NewSessionID(claims.SID)
	if err != nil {
		return domain.ZeroAccessIdentity, err
	}

	email, err := domain.NewEmail(claims.Email)
	if err != nil {
		return domain.ZeroAccessIdentity, err
	}

	var roles []domain.Role
	for _, rName := range claims.Roles {
		role, err := domain.NewRole(rName)
		if err != nil {
			return domain.ZeroAccessIdentity, err
		}
		roles = append(roles, role)
	}

	// 5. Build Identity VO (UserID, SessionID, Email, Roles)
	return domain.NewAccessIdentity(uid, sid, email, roles)
}

package outbound

import (
	"errors"
	"go_auth/internal/domain"
	"time"

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
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	SID         string   `json:"sid"`
	jwt.RegisteredClaims
}

func (p *jwtService) Issue(
	userID domain.UserID,
	email domain.Email,
	sessionID domain.SessionID,
	roles []domain.RoleName,
	permissions []domain.Permission,
	IssuedAt time.Time,
	expiresAt time.Time,
	notBefore time.Time,
) (domain.AccessToken, time.Time, error) {
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name()
	}

	permStrings := make([]string, len(permissions))
	for i, p := range permissions {
		permStrings[i] = p.String()
	}

	claims := CustomClaims{
		Email:       email.String(),
		Roles:       roleNames,
		Permissions: permStrings,
		SID:         sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(IssuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(notBefore),
			Issuer:    p.issuer,
			Audience:  jwt.ClaimStrings{p.audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedStr, err := token.SignedString(p.secretKey)
	if err != nil {
		return domain.ZeroAccessToken, time.Time{}, domain.ErrInternal
	}

	accessToken, err := domain.NewAccessToken(signedStr)
	if err != nil {
		return domain.ZeroAccessToken, time.Time{}, err
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

	var roles []domain.RoleName
	for _, rName := range claims.Roles {
		role, err := domain.NewRoleName(rName)
		if err != nil {
			return domain.ZeroAccessIdentity, err
		}
		roles = append(roles, role)
	}

	var permissions []domain.Permission
	for _, ps := range claims.Permissions {
		p, err := domain.NewPermission(ps)
		if err != nil {
			return domain.ZeroAccessIdentity, err
		}
		permissions = append(permissions, p)
	}

	// 5. Build Identity VO (UserID, SessionID, Email, Roles, Permissions)
	return domain.NewAccessIdentity(uid, sid, email, roles, permissions)
}

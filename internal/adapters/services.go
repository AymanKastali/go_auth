package adapters

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"go_auth/internal/core/domain"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Clock Service
type clock struct{}

func NewClock() domain.IClock {
	return &clock{}
}

// Now returns the current time wrapped in the Domain Value Object.
func (c *clock) Now() domain.Timepoint {
	// We strip monotonic clock readings and normalize to UTC
	// to ensure DB compatibility and consistent comparisons.
	return domain.NewTimepoint(time.Now().UTC())
}

// ID Service
type idGenerator struct{}

func NewIDGenerator() domain.IIDGenerator { return &idGenerator{} }

func (g *idGenerator) GenerateUserID(ctx context.Context) (domain.UserID, error) {
	// Generate a new UUIDv7
	rawID, err := uuid.NewV7()
	if err != nil {
		return domain.ZeroUserID, domain.NewInternalError("failed to generate unique user identity", err)
	}

	userID, err := domain.NewUserID(rawID.String())
	if err != nil {
		// Wrap our local adapter error with the domain validation error
		return domain.ZeroUserID, errors.Join(ErrIDMapping, err)
	}

	return userID, nil
}

func (g *idGenerator) GenerateSessionID(ctx context.Context) (domain.SessionID, error) {
	rawID, err := uuid.NewV7()
	if err != nil {
		return domain.ZeroSessionID, domain.NewInternalError("failed to generate unique session identity", err)
	}

	sessionID, err := domain.NewSessionID(rawID.String())
	if err != nil {
		return domain.ZeroSessionID, errors.Join(ErrIDMapping, err)
	}

	return sessionID, nil
}

// Token Service
type tokenService struct{}

func NewTokenService() domain.ITokenService {
	return &tokenService{}
}

func (s *tokenService) Generate() (domain.RawToken, domain.HashedToken, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return domain.ZeroRawToken, domain.ZeroHashedToken,
			domain.NewInternalError("token generation failed", ErrTokenGeneration)
	}

	rawStr := hex.EncodeToString(b)
	rawToken, err := domain.NewRawToken(rawStr)
	if err != nil {
		return domain.ZeroRawToken, domain.ZeroHashedToken, errors.Join(ErrTokenMapping, err)
	}

	hashedToken, err := s.Hash(rawToken)
	if err != nil {
		return domain.ZeroRawToken, domain.ZeroHashedToken, err
	}

	return rawToken, hashedToken, nil
}

func (s *tokenService) Hash(rawToken domain.RawToken) (domain.HashedToken, error) {
	// Use SHA-256 for opaque token hashing (fast and collision-resistant)
	hash := sha256.Sum256([]byte(rawToken.String()))
	hashedStr := hex.EncodeToString(hash[:])

	return domain.NewHashedToken(hashedStr)
}

func (s *tokenService) Compare(raw domain.RawToken, hashed domain.HashedToken) bool {
	// Re-hash the provided raw token
	actualHash := sha256.Sum256([]byte(raw.String()))
	actualHashStr := hex.EncodeToString(actualHash[:])

	// Use ConstantTimeCompare to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(actualHashStr), []byte(hashed.String())) == 1
}

// Password Service
type passwordService struct{ cost int }

func NewPasswordService(cost int) domain.IPasswordService {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &passwordService{cost: cost}
}

func (s *passwordService) Hash(password domain.RawPassword) (domain.HashedPassword, error) {
	// Bcrypt handles generating a unique salt automatically
	bytes, err := bcrypt.GenerateFromPassword([]byte(password.String()), s.cost)
	if err != nil {
		return domain.ZeroHashedPassword, domain.NewInternalError("password hashing failed", err)
	}

	return domain.NewHashedPassword(string(bytes))
}

func (s *passwordService) Compare(raw domain.RawPassword, hashed domain.HashedPassword) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed.String()), []byte(raw.String()))
	return err == nil
}

// JWT Service
type jwtProvider struct {
	secretKey []byte
	expiry    time.Duration
	issuer    string
	audience  string
}

func NewAccessTokenProvider(
	secret string,
	expiry time.Duration,
	issuer string,
	audience string,
) domain.IAccessTokenProvider {
	return &jwtProvider{
		secretKey: []byte(secret),
		expiry:    expiry,
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

func (p *jwtProvider) Generate(
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
		return domain.ZeroAccessToken, domain.ZeroTimepoint,
			domain.NewInternalError("failed to sign access token", err)
	}

	accessToken, err := domain.NewAccessToken(signedStr)
	if err != nil {
		return domain.ZeroAccessToken, domain.ZeroTimepoint, err
	}

	return accessToken, expiresAt, nil
}

// func (p *jwtProvider) Generate(
// 	user *domain.User,
// 	sid domain.SessionID,
// ) (domain.AccessToken, domain.Timepoint, error) {
// 	now := time.Now().UTC()
// 	expiryTime := now.Add(p.expiry)

// 	roleNames := make([]string, len(user.Roles()))
// 	for i, r := range user.Roles() {
// 		roleNames[i] = r.Name()
// 	}

// 	claims := CustomClaims{
// 		Email: user.Email().String(),
// 		Roles: roleNames,
// 		SID:   sid.String(), // Link to database session
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			Subject:   user.ID().String(),
// 			ExpiresAt: jwt.NewNumericDate(expiryTime),
// 			IssuedAt:  jwt.NewNumericDate(now),
// 			NotBefore: jwt.NewNumericDate(now),
// 			Issuer:    p.issuer,
// 			Audience:  jwt.ClaimStrings{p.audience},
// 		},
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	signedStr, err := token.SignedString(p.secretKey)
// 	if err != nil {
// 		return domain.ZeroAccessToken, domain.ZeroTimepoint,
// 			domain.NewInternalError("failed to sign access token", err)
// 	}

// 	accessToken, err := domain.NewAccessToken(signedStr)
// 	if err != nil {
// 		return domain.ZeroAccessToken, domain.ZeroTimepoint, err
// 	}

//		return accessToken, domain.NewTimepoint(expiryTime), nil
//	}
func (p *jwtProvider) Validate(token domain.AccessToken) (domain.AccessIdentity, error) {
	// 1. Technical Parse with Claims Validation
	parsedToken, err := jwt.ParseWithClaims(
		token.String(),
		&CustomClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return p.secretKey, nil
		},
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.audience),
	)

	// 2. Map Infrastructure Errors
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("token expired")
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) || errors.Is(err, jwt.ErrTokenInvalidAudience) {
			return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("untrusted token source")
		}
		return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("invalid token")
	}

	// 3. Technical Extraction
	claims, ok := parsedToken.Claims.(*CustomClaims)
	if !ok || !parsedToken.Valid {
		return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("invalid claims")
	}

	// 4. Reconstitute Domain VOs
	uid, err := domain.NewUserID(claims.Subject)
	if err != nil {
		return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("invalid uid in token")
	}

	// Use the Custom SID claim, NOT the JTI
	sid, err := domain.NewSessionID(claims.SID)
	if err != nil {
		return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("invalid sid in token")
	}

	email, err := domain.NewEmail(claims.Email)
	if err != nil {
		return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("invalid email in token")
	}

	var roles []domain.Role
	for _, rName := range claims.Roles {
		role, err := domain.NewRole(rName)
		if err != nil {
			return domain.ZeroAccessIdentity, domain.NewInvalidIdentityError("invalid role in token")
		}
		roles = append(roles, role)
	}

	// 5. Build Identity VO (UserID, SessionID, Email, Roles)
	return domain.NewAccessIdentity(uid, sid, email, roles)
}

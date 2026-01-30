package adapters

import (
	"go_auth/internal/core/domain"

	"golang.org/x/crypto/bcrypt"
)

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
		return domain.ZeroHashedPassword, domain.ErrInternal
	}

	return domain.NewHashedPassword(string(bytes))
}

func (s *passwordService) Compare(raw domain.RawPassword, hashed domain.HashedPassword) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed.String()), []byte(raw.String())) == nil
}

package services

import (
	"crypto/rand"
	"encoding/base64"
	"go_auth/internal/core/domain/valueobjects"
)

type cryptoRandomTokenGeneratorService struct {
	size int
}

func NewCryptoRandomTokenGenerator(size int) *cryptoRandomTokenGeneratorService {
	return &cryptoRandomTokenGeneratorService{size: size}
}

func (g *cryptoRandomTokenGeneratorService) Generate() (valueobjects.SessionRenewalRawTokenSecret, error) {
	b := make([]byte, g.size)
	if _, err := rand.Read(b); err != nil {
		return valueobjects.SessionRenewalRawTokenSecret{}, err
	}
	encodedStr := base64.RawURLEncoding.EncodeToString(b)
	secretVO, err := valueobjects.NewSessionRenewalRawTokenSecret(encodedStr)
	if err != nil {
		return valueobjects.SessionRenewalRawTokenSecret{}, err
	}
	return secretVO, nil
}

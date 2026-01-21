package services

import (
	"crypto/rand"
	"encoding/base64"
)

type cryptoRandomTokenGeneratorService struct{}

func NewCryptoRandomTokenGenerator() *cryptoRandomTokenGeneratorService {
	return &cryptoRandomTokenGeneratorService{}
}

func (g *cryptoRandomTokenGeneratorService) Generate(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

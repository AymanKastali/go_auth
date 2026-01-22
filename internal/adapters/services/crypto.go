package services

import (
	"crypto/rand"
	"encoding/base64"
)

type cryptoRandomTokenGeneratorService struct {
	size int
}

func NewCryptoRandomTokenGenerator(size int) *cryptoRandomTokenGeneratorService {
	return &cryptoRandomTokenGeneratorService{size: size}
}

func (g *cryptoRandomTokenGeneratorService) Generate() (string, error) {
	b := make([]byte, g.size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

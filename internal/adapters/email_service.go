package adapters

import (
	"fmt"
	"go_auth/internal/core/application"
)

// Email
type emailService struct {
	config EmailConfig
}

func NewEmailService(cfg EmailConfig) application.IEmailService {
	return &emailService{config: cfg}
}

func (s *emailService) SendResetLink(toEmail string, rawToken string) error {
	// For now, we log it. In production, use net/smtp or an API.
	fmt.Printf("Sending reset link to %s: http://yourapp.com/reset?token=%s\n", toEmail, rawToken)
	return nil
}

package adapters

import (
	"fmt"
	"net/smtp"

	"go_auth/internal/core/application"
)

type emailService struct {
	config EmailConfig
}

func NewEmailService(cfg EmailConfig) application.IEmailService {
	return &emailService{config: cfg}
}

func (s *emailService) SendResetLink(toEmail string, rawToken string) error {
	resetLink := fmt.Sprintf("%s?token=%s", s.config.ResetBaseURL, rawToken)

	subject := "Password Reset Request"
	body := fmt.Sprintf(
		"You have requested a password reset.\r\n\r\n"+
			"Click the link below to reset your password:\r\n%s\r\n\r\n"+
			"If you did not request this, please ignore this email.",
		resetLink,
	)

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n%s",
		s.config.From, toEmail, subject, body,
	)

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	var auth smtp.Auth
	if s.config.Username != "" {
		auth = smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	}

	return smtp.SendMail(addr, auth, s.config.From, []string{toEmail}, []byte(msg))
}

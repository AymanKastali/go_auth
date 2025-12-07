package usecases

import (
	"context"
	"go_auth/src/application/dto"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/services"
	valueobjects "go_auth/src/domain/value_objects"
)

type LoginHandler struct {
	AuthSvc *services.AuthenticateUser
}

func NewLoginHandler(auth *services.AuthenticateUser) *LoginHandler {
	return &LoginHandler{AuthSvc: auth}
}

func (h *LoginHandler) Handle(ctx context.Context, req dto.LoginRequest) (*dto.AuthResponse, error) {
	// 1️⃣ Validate email
	emailVO, err := valueobjects.NewEmail(req.Email)
	if err != nil {
		return nil, err
	}

	// 2️⃣ Authenticate user and get stateless JWT
	token, err := h.AuthSvc.Execute(emailVO, req.Password)
	if err != nil {
		return nil, errors.ErrInvalidCredentials
	}

	// 3️⃣ Build response
	return &dto.AuthResponse{
		AccessToken: token.Value(),
		// No refresh token — fully stateless
	}, nil
}

package handlers

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/services"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
)

type LoginHandler struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher services.HashPasswordPort
	tokenService   services.TokenServicePort
	emailFactory   factories.EmailFactory
}

func NewLoginHandler(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
	tokenService services.TokenServicePort,
	emailFactory factories.EmailFactory,
) *LoginHandler {
	return &LoginHandler{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		emailFactory:   emailFactory,
	}
}

func (h *LoginHandler) Execute(email string, password string) (*dto.AuthResponse, error) {

	emailVO, err := h.emailFactory.New(email)
	if err != nil {
	}

	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		return nil, errors.ErrInvalidCredentials
	}
	if user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	if !h.passwordHasher.Compare(password, user.PasswordHash.Value) {
		return nil, errors.ErrInvalidCredentials
	}

	userIDStr := user.ID.Value.String()

	accessToken, err := h.tokenService.IssueAccessToken(userIDStr)
	if err != nil {
		return nil, err
	}
	refreshToken, err := h.tokenService.IssueRefreshToken(userIDStr)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}

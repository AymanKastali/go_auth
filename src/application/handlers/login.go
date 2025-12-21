package handlers

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/security"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
)

type LoginHandler struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher security.HashPasswordPort
	tokenService   security.TokenServicePort
	emailFactory   factories.EmailFactory
}

func NewLoginHandler(
	userRepository repositories.UserRepositoryPort,
	passwordHasher security.HashPasswordPort,
	tokenService security.TokenServicePort,
	emailFactory factories.EmailFactory,
) *LoginHandler {
	return &LoginHandler{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		emailFactory:   emailFactory,
	}
}

func (h *LoginHandler) Execute(
	email string,
	password string,
) (*dto.AuthResponse, error) {

	// --- Parse and validate email ---
	emailVO, err := h.emailFactory.New(email)
	if err != nil {
		return nil, err
	}

	// --- Fetch user ---
	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil || user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	// --- Validate password ---
	if !h.passwordHasher.Compare(password, user.PasswordHash.Value) {
		return nil, errors.ErrInvalidCredentials
	}

	// --- Convert IDs to strings for JWT / token service ---
	userIDStr := user.ID.Value.String()

	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	// --- Issue tokens ---
	accessToken, err := h.tokenService.IssueAccessToken(userIDStr, roles)
	if err != nil {
		return nil, err
	}

	refreshToken, err := h.tokenService.IssueRefreshToken(userIDStr)
	if err != nil {
		return nil, err
	}

	// --- Return response ---
	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}

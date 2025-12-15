package usecases

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/services"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
)

type LoginUseCase struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher services.HashPasswordPort
	tokenService   services.TokenServicePort
	emailFactory   factories.EmailFactory
}

func NewLoginUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
	tokenService services.TokenServicePort,
	emailFactory factories.EmailFactory,
) *LoginUseCase {
	return &LoginUseCase{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		emailFactory:   emailFactory,
	}
}

func (uc *LoginUseCase) Execute(email string, password string) (*dto.AuthResponse, error) {

	emailVO, err := uc.emailFactory.New(email)
	if err != nil {
	}

	user, err := uc.userRepository.GetByEmail(emailVO)
	if err != nil {
		return nil, errors.ErrInvalidCredentials
	}
	if user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	if !uc.passwordHasher.Compare(password, user.PasswordHash.Value) {
		return nil, errors.ErrInvalidCredentials
	}

	userIDStr := user.ID.Value.String()

	accessToken, err := uc.tokenService.IssueAccessToken(userIDStr)
	if err != nil {
		return nil, err
	}
	refreshToken, err := uc.tokenService.IssueRefreshToken(userIDStr)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}

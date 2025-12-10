package usecases

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/services"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"
)

type LoginUseCase struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher services.HashPasswordPort
	tokenService   services.TokenServicePort
}

func NewLoginUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
	tokenService services.TokenServicePort,
) *LoginUseCase {
	return &LoginUseCase{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
	}
}

func (uc *LoginUseCase) Execute(email string, password string) (*dto.AuthResponse, error) {
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, err
	}

	user, err := uc.userRepository.GetByEmail(emailVO)
	if err != nil || user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	if !uc.passwordHasher.Compare(password, user.PasswordHash().Value()) {
		return nil, errors.ErrInvalidCredentials
	}

	accessToken, err := uc.tokenService.IssueAccessToken(user)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		AccessToken: accessToken.Value(),
	}, nil
}

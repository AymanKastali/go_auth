package usecases

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/services"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
)

func mapRolesToNames(roles []entities.Role) []string {
	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}
	return roleNames
}

type LoginUseCase struct {
	UserRepository repositories.UserRepositoryPort
	PasswordHasher services.HashPasswordPort
	TokenService   services.TokenServicePort
	EmailFactory   factories.EmailFactory
}

func NewLoginUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
	tokenService services.TokenServicePort,
	emailFactory factories.EmailFactory,
) *LoginUseCase {
	return &LoginUseCase{
		UserRepository: userRepository,
		PasswordHasher: passwordHasher,
		TokenService:   tokenService,
		EmailFactory:   emailFactory,
	}
}

func (uc *LoginUseCase) Execute(email string, password string) (*dto.AuthResponse, error) {

	emailVO, err := uc.EmailFactory.New(email)
	if err != nil {
	}

	user, err := uc.UserRepository.GetByEmail(emailVO)

	if err != nil {
		return nil, errors.ErrInvalidCredentials
	}
	if user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	if !uc.PasswordHasher.Compare(password, user.PasswordHash.Value) {
		return nil, errors.ErrInvalidCredentials
	}

	roleNames := mapRolesToNames(user.Roles)

	userIDStr := user.ID.Value.String()

	accessToken, err := uc.TokenService.IssueAccessToken(userIDStr, roleNames)
	if err != nil {
		return nil, err
	}
	refreshToken, err := uc.TokenService.IssueRefreshToken(userIDStr)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}

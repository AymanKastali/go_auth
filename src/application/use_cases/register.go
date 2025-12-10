package usecases

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/events"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"

	"go_auth/src/application/ports/services"
)

type RegisterUseCase struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher services.HashPasswordPort
}

func NewRegisterUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
	}
}

func (uc *RegisterUseCase) Execute(email string, password string) (*dto.AuthResponse, error) {
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, err
	}

	// check existence
	existing, _ := uc.userRepository.GetByEmail(emailVO)
	if existing != nil {
		return nil, errors.ErrEmailAlreadyRegistered
	}

	// hash password
	hash, err := uc.passwordHasher.Hash(password)
	if err != nil {
		return nil, err
	}
	pw := valueobjects.NewPasswordHash(hash)
	uid := valueobjects.NewUserID()
	user := entities.NewUser(uid, emailVO, pw)

	if err := uc.userRepository.Save(user); err != nil {
		return nil, err
	}

	// publish event (omitted: just demonstrate)
	_ = events.UserRegistered{UserID: uid}

	// Return nothing (or auto-login if you prefer). We'll return nil for now.
	return nil, nil
}

package usecases

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/events"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"

	"go_auth/src/application/ports/services"
)

type RegisterUseCase struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher services.HashPasswordPort
	// factories
	idFactory      factories.IDFactory
	emailFactory   factories.EmailFactory
	pwdHashFactory factories.PasswordHashFactory
	userFactory    factories.UserFactory
}

func NewRegisterUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
	idFactory factories.IDFactory,
	emailFactory factories.EmailFactory,
	pwHashFactory factories.PasswordHashFactory,
	userFactory factories.UserFactory,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		idFactory:      idFactory,
		emailFactory:   emailFactory,
		pwdHashFactory: pwHashFactory,
		userFactory:    userFactory,
	}
}

func (uc *RegisterUseCase) Execute(email string, password string) (*dto.AuthResponse, error) {

	// Use the injected factory
	emailVO, err := uc.emailFactory.New(email)
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

	// Use the injected factory
	pw := uc.pwdHashFactory.New(hash)

	// Use the injected factory
	user := uc.userFactory.New(
		uc.idFactory.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
	)

	if err := uc.userRepository.Save(user); err != nil {
		return nil, err
	}

	// publish event (omitted: just demonstrate)
	_ = events.UserRegistered{UserID: user.ID}

	return nil, nil
}

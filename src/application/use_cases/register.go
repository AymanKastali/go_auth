package usecases

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/events"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"

	"go_auth/src/application/ports/services"
)

type RegisterUseCase struct {
	UserRepository repositories.UserRepositoryPort
	PasswordHasher services.HashPasswordPort
	// factories
	EmailFactory   factories.EmailFactory
	PwdHashFactory factories.PasswordHashFactory
	RoleFactory    factories.RoleFactory
	UserFactory    factories.UserFactory
}

func NewRegisterUseCase(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
	emailFactory factories.EmailFactory,
	pwHashFactory factories.PasswordHashFactory,
	roleFactory factories.RoleFactory,
	userFactory factories.UserFactory,
) *RegisterUseCase {
	return &RegisterUseCase{
		UserRepository: userRepository,
		PasswordHasher: passwordHasher,
		EmailFactory:   emailFactory,
		PwdHashFactory: pwHashFactory,
		RoleFactory:    roleFactory,
		UserFactory:    userFactory,
	}
}

func (uc *RegisterUseCase) Execute(email string, password string) (*dto.AuthResponse, error) {

	// Use the injected factory
	emailVO, err := uc.EmailFactory.New(email)
	if err != nil {
		return nil, err
	}

	// check existence
	existing, _ := uc.UserRepository.GetByEmail(emailVO)
	if existing != nil {
		return nil, errors.ErrEmailAlreadyRegistered
	}

	// hash password
	hash, err := uc.PasswordHasher.Hash(password)
	if err != nil {
		return nil, err
	}

	// Use the injected factory
	pw := uc.PwdHashFactory.New(hash)

	// Use the injected factory
	defaultRole, err := uc.RoleFactory.NewDefaultUserRole()
	if err != nil {
		return nil, err
	}
	defaultRoles := []entities.Role{*defaultRole}

	// Use the injected factory
	user := uc.UserFactory.New(emailVO, pw, defaultRoles, true)

	if err := uc.UserRepository.Save(user); err != nil {
		return nil, err
	}

	// publish event (omitted: just demonstrate)
	_ = events.UserRegistered{UserID: user.ID}

	return nil, nil
}
